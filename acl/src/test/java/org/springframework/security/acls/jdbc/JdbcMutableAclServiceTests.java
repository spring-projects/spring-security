/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.acls.jdbc;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.sql.DataSource;

import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.acls.AccessControlEntry;
import org.springframework.security.acls.Acl;
import org.springframework.security.acls.AlreadyExistsException;
import org.springframework.security.acls.ChildrenExistException;
import org.springframework.security.acls.MutableAcl;
import org.springframework.security.acls.NotFoundException;
import org.springframework.security.acls.Permission;
import org.springframework.security.acls.TargetObject;
import org.springframework.security.acls.domain.AclImpl;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.CumulativePermission;
import org.springframework.security.acls.objectidentity.ObjectIdentity;
import org.springframework.security.acls.objectidentity.ObjectIdentityImpl;
import org.springframework.security.acls.sid.GrantedAuthoritySid;
import org.springframework.security.acls.sid.PrincipalSid;
import org.springframework.security.acls.sid.Sid;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.AbstractTransactionalJUnit4SpringContextTests;
import org.springframework.test.context.transaction.AfterTransaction;
import org.springframework.test.context.transaction.BeforeTransaction;
import org.springframework.transaction.annotation.Transactional;

/**
 * Integration tests the ACL system using an in-memory database.
 *
 * @author Ben Alex
 * @author Andrei Stefan
 * @version $Id:JdbcMutableAclServiceTests.java 1754 2006-11-17 02:01:21Z benalex $
 */
@ContextConfiguration(locations={"/jdbcMutableAclServiceTests-context.xml"})
public class JdbcMutableAclServiceTests extends AbstractTransactionalJUnit4SpringContextTests {
    //~ Constant fields ================================================================================================

    private static final String TARGET_CLASS = TargetObject.class.getName();

    private final Authentication auth = new TestingAuthenticationToken("ben", "ignored","ROLE_ADMINISTRATOR");

    public static final String SELECT_ALL_CLASSES = "SELECT * FROM acl_class WHERE class = ?";

    //~ Instance fields ================================================================================================

    private final ObjectIdentity topParentOid = new ObjectIdentityImpl(TARGET_CLASS, Long.valueOf(100));
    private final ObjectIdentity middleParentOid = new ObjectIdentityImpl(TARGET_CLASS, Long.valueOf(101));
    private final ObjectIdentity childOid = new ObjectIdentityImpl(TARGET_CLASS, Long.valueOf(102));

    @Autowired
    private JdbcMutableAclService jdbcMutableAclService;
    @Autowired
    private AclCache aclCache;
    @Autowired
    private LookupStrategy lookupStrategy;
    @Autowired
    private DataSource dataSource;
    @Autowired
    private JdbcTemplate jdbcTemplate;

    //~ Methods ========================================================================================================

    @BeforeTransaction
    public void createTables() throws Exception {
        try {
            new DatabaseSeeder(dataSource, new ClassPathResource("createAclSchema.sql"));
//            new DatabaseSeeder(dataSource, new ClassPathResource("createAclSchemaPostgres.sql"));
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
    }

    @AfterTransaction
    public void clearContextAndData() throws Exception {
        SecurityContextHolder.clearContext();
        jdbcTemplate.execute("drop table acl_entry");
        jdbcTemplate.execute("drop table acl_object_identity");
        jdbcTemplate.execute("drop table acl_class");
        jdbcTemplate.execute("drop table acl_sid");
    }

    @Test
    @Transactional
    public void testLifecycle() {
        SecurityContextHolder.getContext().setAuthentication(auth);

        MutableAcl topParent = jdbcMutableAclService.createAcl(topParentOid);
        MutableAcl middleParent = jdbcMutableAclService.createAcl(middleParentOid);
        MutableAcl child = jdbcMutableAclService.createAcl(childOid);

        // Specify the inheritance hierarchy
        middleParent.setParent(topParent);
        child.setParent(middleParent);

        // Now let's add a couple of permissions
        topParent.insertAce(0, BasePermission.READ, new PrincipalSid(auth), true);
        topParent.insertAce(1, BasePermission.WRITE, new PrincipalSid(auth), false);
        middleParent.insertAce(0, BasePermission.DELETE, new PrincipalSid(auth), true);
        child.insertAce(0, BasePermission.DELETE, new PrincipalSid(auth), false);

        // Explicitly save the changed ACL
        jdbcMutableAclService.updateAcl(topParent);
        jdbcMutableAclService.updateAcl(middleParent);
        jdbcMutableAclService.updateAcl(child);

        // Let's check if we can read them back correctly
        Map<ObjectIdentity, Acl> map = jdbcMutableAclService.readAclsById(Arrays.asList(topParentOid, middleParentOid, childOid));
        assertEquals(3, map.size());

        // Replace our current objects with their retrieved versions
        topParent = (MutableAcl) map.get(topParentOid);
        middleParent = (MutableAcl) map.get(middleParentOid);
        child = (MutableAcl) map.get(childOid);

        // Check the retrieved versions has IDs
        assertNotNull(topParent.getId());
        assertNotNull(middleParent.getId());
        assertNotNull(child.getId());

        // Check their parents were correctly persisted
        assertNull(topParent.getParentAcl());
        assertEquals(topParentOid, middleParent.getParentAcl().getObjectIdentity());
        assertEquals(middleParentOid, child.getParentAcl().getObjectIdentity());

        // Check their ACEs were correctly persisted
        assertEquals(2, topParent.getEntries().size());
        assertEquals(1, middleParent.getEntries().size());
        assertEquals(1, child.getEntries().size());

        // Check the retrieved rights are correct
        List<Permission> read = Arrays.asList(BasePermission.READ);
        List<Permission> write = Arrays.asList(BasePermission.WRITE);
        List<Permission> delete = Arrays.asList(BasePermission.DELETE);
        List<Sid> pSid = Arrays.asList((Sid)new PrincipalSid(auth));


        assertTrue(topParent.isGranted(read, pSid, false));
        assertFalse(topParent.isGranted(write, pSid, false));
        assertTrue(middleParent.isGranted(delete, pSid, false));
        assertFalse(child.isGranted(delete, pSid, false));

        try {
            child.isGranted(Arrays.asList(BasePermission.ADMINISTRATION), pSid, false);
            fail("Should have thrown NotFoundException");
        } catch (NotFoundException expected) {
            assertTrue(true);
        }

        // Now check the inherited rights (when not explicitly overridden) also look OK
        assertTrue(child.isGranted(read, pSid, false));
        assertFalse(child.isGranted(write, pSid, false));
        assertFalse(child.isGranted(delete, pSid, false));

        // Next change the child so it doesn't inherit permissions from above
        child.setEntriesInheriting(false);
        jdbcMutableAclService.updateAcl(child);
        child = (MutableAcl) jdbcMutableAclService.readAclById(childOid);
        assertFalse(child.isEntriesInheriting());

        // Check the child permissions no longer inherit
        assertFalse(child.isGranted(delete, pSid, true));

        try {
            child.isGranted(read, pSid, true);
            fail("Should have thrown NotFoundException");
        } catch (NotFoundException expected) {
            assertTrue(true);
        }

        try {
            child.isGranted(write, pSid, true);
            fail("Should have thrown NotFoundException");
        } catch (NotFoundException expected) {
            assertTrue(true);
        }

        // Let's add an identical permission to the child, but it'll appear AFTER the current permission, so has no impact
        child.insertAce(1, BasePermission.DELETE, new PrincipalSid(auth), true);

        // Let's also add another permission to the child
        child.insertAce(2, BasePermission.CREATE, new PrincipalSid(auth), true);

        // Save the changed child
        jdbcMutableAclService.updateAcl(child);
        child = (MutableAcl) jdbcMutableAclService.readAclById(childOid);
        assertEquals(3, child.getEntries().size());

        // Output permissions
        for (int i = 0; i < child.getEntries().size(); i++) {
            System.out.println(child.getEntries().get(i));
        }

        // Check the permissions are as they should be
        assertFalse(child.isGranted(delete, pSid, true)); // as earlier permission overrode
        assertTrue(child.isGranted(Arrays.asList(BasePermission.CREATE), pSid, true));

        // Now check the first ACE (index 0) really is DELETE for our Sid and is non-granting
        AccessControlEntry entry = child.getEntries().get(0);
        assertEquals(BasePermission.DELETE.getMask(), entry.getPermission().getMask());
        assertEquals(new PrincipalSid(auth), entry.getSid());
        assertFalse(entry.isGranting());
        assertNotNull(entry.getId());

        // Now delete that first ACE
        child.deleteAce(0);

        // Save and check it worked
        child = jdbcMutableAclService.updateAcl(child);
        assertEquals(2, child.getEntries().size());
        assertTrue(child.isGranted(delete, pSid, false));

        SecurityContextHolder.clearContext();
    }

    /**
     * Test method that demonstrates eviction failure from cache - SEC-676
     */
    @Test
    @Transactional
    public void deleteAclAlsoDeletesChildren() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(auth);

        jdbcMutableAclService.createAcl(topParentOid);
        MutableAcl middleParent = jdbcMutableAclService.createAcl(middleParentOid);
        MutableAcl child = jdbcMutableAclService.createAcl(childOid);
        child.setParent(middleParent);
        jdbcMutableAclService.updateAcl(middleParent);
        jdbcMutableAclService.updateAcl(child);
        // Check the childOid really is a child of middleParentOid
        Acl childAcl = jdbcMutableAclService.readAclById(childOid);

        assertEquals(middleParentOid, childAcl.getParentAcl().getObjectIdentity());

        // Delete the mid-parent and test if the child was deleted, as well
        jdbcMutableAclService.deleteAcl(middleParentOid, true);

        try {
            jdbcMutableAclService.readAclById(middleParentOid);
            fail("It should have thrown NotFoundException");
        }
        catch (NotFoundException expected) {
            assertTrue(true);
        }
        try {
            jdbcMutableAclService.readAclById(childOid);
            fail("It should have thrown NotFoundException");
        }
        catch (NotFoundException expected) {
            assertTrue(true);
        }

        Acl acl = jdbcMutableAclService.readAclById(topParentOid);
        assertNotNull(acl);
        assertEquals(((MutableAcl) acl).getObjectIdentity(), topParentOid);
    }

    @Test
    public void constructorRejectsNullParameters() throws Exception {
        try {
            new JdbcMutableAclService(null, lookupStrategy, aclCache);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
        }

        try {
            new JdbcMutableAclService(dataSource, null, aclCache);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
        }

        try {
            new JdbcMutableAclService(dataSource, lookupStrategy, null);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void createAclRejectsNullParameter() throws Exception {
        try {
            jdbcMutableAclService.createAcl(null);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
        }
    }

    @Test
    @Transactional
    public void createAclForADuplicateDomainObject() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(auth);
        ObjectIdentity duplicateOid = new ObjectIdentityImpl(TARGET_CLASS, Long.valueOf(100));
        jdbcMutableAclService.createAcl(duplicateOid);
        // Try to add the same object second time
        try {
            jdbcMutableAclService.createAcl(duplicateOid);
            fail("It should have thrown AlreadyExistsException");
        }
        catch (AlreadyExistsException expected) {
        }
    }

    @Test
    @Transactional
    public void deleteAclRejectsNullParameters() throws Exception {
        try {
            jdbcMutableAclService.deleteAcl(null, true);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
        }
    }

    @Test
    @Transactional
    public void deleteAclWithChildrenThrowsException() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(auth);
        MutableAcl parent = jdbcMutableAclService.createAcl(topParentOid);
        MutableAcl child = jdbcMutableAclService.createAcl(middleParentOid);

        // Specify the inheritance hierarchy
        child.setParent(parent);
        jdbcMutableAclService.updateAcl(child);

        try {
            jdbcMutableAclService.setForeignKeysInDatabase(false); // switch on FK checking in the class, not database
            jdbcMutableAclService.deleteAcl(topParentOid, false);
            fail("It should have thrown ChildrenExistException");
        }
        catch (ChildrenExistException expected) {
        } finally {
            jdbcMutableAclService.setForeignKeysInDatabase(true); // restore to the default
        }
    }

    @Test
    @Transactional
    public void deleteAclRemovesRowsFromDatabase() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(auth);
        MutableAcl child = jdbcMutableAclService.createAcl(childOid);
        child.insertAce(0, BasePermission.DELETE, new PrincipalSid(auth), false);
        jdbcMutableAclService.updateAcl(child);

        // Remove the child and check all related database rows were removed accordingly
        jdbcMutableAclService.deleteAcl(childOid, false);
        assertEquals(1, jdbcTemplate.queryForList(SELECT_ALL_CLASSES, new Object[] {TARGET_CLASS} ).size());
        assertEquals(0, jdbcTemplate.queryForList("select * from acl_object_identity").size());
        assertEquals(0, jdbcTemplate.queryForList("select * from acl_entry").size());

        // Check the cache
        assertNull(aclCache.getFromCache(childOid));
        assertNull(aclCache.getFromCache(Long.valueOf(102)));
    }

    /** SEC-1107 */
    @Test
    @Transactional
    public void identityWithIntegerIdIsSupportedByCreateAcl() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(auth);
        ObjectIdentity oid = new ObjectIdentityImpl(TARGET_CLASS, Integer.valueOf(101));
        jdbcMutableAclService.createAcl(oid);

        assertNotNull(jdbcMutableAclService.readAclById(new ObjectIdentityImpl(TARGET_CLASS, Long.valueOf(101))));
    }

    /**
     * SEC-655
     */
    @Test
    @Transactional
    public void childrenAreClearedFromCacheWhenParentIsUpdated() throws Exception {
        Authentication auth = new TestingAuthenticationToken("ben", "ignored","ROLE_ADMINISTRATOR");
        auth.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(auth);

        ObjectIdentity parentOid = new ObjectIdentityImpl(TARGET_CLASS, Long.valueOf(104));
        ObjectIdentity childOid = new ObjectIdentityImpl(TARGET_CLASS, Long.valueOf(105));

        MutableAcl parent = jdbcMutableAclService.createAcl(parentOid);
        MutableAcl child = jdbcMutableAclService.createAcl(childOid);

        child.setParent(parent);
        jdbcMutableAclService.updateAcl(child);

        parent = (AclImpl) jdbcMutableAclService.readAclById(parentOid);
        parent.insertAce(0, BasePermission.READ, new PrincipalSid("ben"), true);
        jdbcMutableAclService.updateAcl(parent);

        parent = (AclImpl) jdbcMutableAclService.readAclById(parentOid);
        parent.insertAce(1, BasePermission.READ, new PrincipalSid("scott"), true);
        jdbcMutableAclService.updateAcl(parent);

        child = (MutableAcl) jdbcMutableAclService.readAclById(childOid);
        parent = (MutableAcl) child.getParentAcl();

        assertEquals("Fails because child has a stale reference to its parent", 2, parent.getEntries().size());
        assertEquals(1, parent.getEntries().get(0).getPermission().getMask());
        assertEquals(new PrincipalSid("ben"), parent.getEntries().get(0).getSid());
        assertEquals(1, parent.getEntries().get(1).getPermission().getMask());
        assertEquals(new PrincipalSid("scott"), parent.getEntries().get(1).getSid());
    }

    /**
     * SEC-655
     */
    @Test
    @Transactional
    public void childrenAreClearedFromCacheWhenParentisUpdated2() throws Exception {
        Authentication auth = new TestingAuthenticationToken("system", "secret","ROLE_IGNORED");
        SecurityContextHolder.getContext().setAuthentication(auth);
        ObjectIdentityImpl rootObject = new ObjectIdentityImpl(TARGET_CLASS, Long.valueOf(1));

        MutableAcl parent = jdbcMutableAclService.createAcl(rootObject);
        MutableAcl child = jdbcMutableAclService.createAcl(new ObjectIdentityImpl(TARGET_CLASS, Long.valueOf(2)));
        child.setParent(parent);
        jdbcMutableAclService.updateAcl(child);

        parent.insertAce(0, BasePermission.ADMINISTRATION, new GrantedAuthoritySid("ROLE_ADMINISTRATOR"), true);
        jdbcMutableAclService.updateAcl(parent);

        parent.insertAce(1, BasePermission.DELETE, new PrincipalSid("terry"), true);
        jdbcMutableAclService.updateAcl(parent);

        child = (MutableAcl) jdbcMutableAclService.readAclById(new ObjectIdentityImpl(TARGET_CLASS, Long.valueOf(2)));

        parent = (MutableAcl) child.getParentAcl();

        assertEquals(2, parent.getEntries().size());
        assertEquals(16, parent.getEntries().get(0).getPermission().getMask());
        assertEquals(new GrantedAuthoritySid("ROLE_ADMINISTRATOR"), parent.getEntries().get(0).getSid());
        assertEquals(8, parent.getEntries().get(1).getPermission().getMask());
        assertEquals(new PrincipalSid("terry"), parent.getEntries().get(1).getSid());
    }

    @Test
    @Transactional
    public void cumulativePermissions() {
       Authentication auth = new TestingAuthenticationToken("ben", "ignored", "ROLE_ADMINISTRATOR");
       auth.setAuthenticated(true);
       SecurityContextHolder.getContext().setAuthentication(auth);

       ObjectIdentity topParentOid = new ObjectIdentityImpl(TARGET_CLASS, Long.valueOf(110));
       MutableAcl topParent = jdbcMutableAclService.createAcl(topParentOid);

       // Add an ACE permission entry
       Permission cm = new CumulativePermission().set(BasePermission.READ).set(BasePermission.ADMINISTRATION);
       assertEquals(17, cm.getMask());
       Sid benSid = new PrincipalSid(auth);
       topParent.insertAce(0, cm, benSid, true);
       assertEquals(1, topParent.getEntries().size());

       // Explicitly save the changed ACL
       topParent = jdbcMutableAclService.updateAcl(topParent);

       // Check the mask was retrieved correctly
       assertEquals(17, topParent.getEntries().get(0).getPermission().getMask());
       assertTrue(topParent.isGranted(Arrays.asList(cm), Arrays.asList(benSid), true));

       SecurityContextHolder.clearContext();
   }

}
