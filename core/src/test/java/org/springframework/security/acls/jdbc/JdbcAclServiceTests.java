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

import java.util.Map;

import org.springframework.security.Authentication;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.acls.AccessControlEntry;
import org.springframework.security.acls.AlreadyExistsException;
import org.springframework.security.acls.ChildrenExistException;
import org.springframework.security.acls.MutableAcl;
import org.springframework.security.acls.NotFoundException;
import org.springframework.security.acls.Permission;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.objectidentity.ObjectIdentity;
import org.springframework.security.acls.objectidentity.ObjectIdentityImpl;
import org.springframework.security.acls.sid.PrincipalSid;
import org.springframework.security.acls.sid.Sid;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.TestingAuthenticationToken;
import org.springframework.test.AbstractTransactionalDataSourceSpringContextTests;


/**
 * Integration tests the ACL system using an in-memory database.
 *
 * @author Ben Alex
 * @author Andrei Stefan
 * @version $Id:JdbcAclServiceTests.java 1754 2006-11-17 02:01:21Z benalex $
 */
public class JdbcAclServiceTests extends AbstractTransactionalDataSourceSpringContextTests {
    //~ Constant fields ================================================================================================
    
    public static final String SELECT_ALL_CLASSES = "SELECT * FROM acl_class WHERE class = ?";
    
    public static final String SELECT_ALL_OBJECT_IDENTITIES = "SELECT * FROM acl_object_identity";
    
    public static final String SELECT_OBJECT_IDENTITY = "SELECT * FROM acl_object_identity WHERE object_id_identity = ?";
    
    public static final String SELECT_ACL_ENTRY = "SELECT * FROM acl_entry, acl_object_identity WHERE " +
            "acl_object_identity.id = acl_entry.acl_object_identity " +
            "AND acl_object_identity.object_id_identity <= ?";

    //~ Instance fields ================================================================================================
    
    private JdbcMutableAclService jdbcMutableAclService;
    
    private AclCache aclCache;
    
    private LookupStrategy lookupStrategy;

    //~ Methods ========================================================================================================

    protected String[] getConfigLocations() {
        return new String[] {"classpath:org/springframework/security/acls/jdbc/applicationContext-test.xml"};
    }

    public void setJdbcMutableAclService(JdbcMutableAclService jdbcAclService) {
        this.jdbcMutableAclService = jdbcAclService;
    }

    public void setAclCache(AclCache aclCache) {
        this.aclCache = aclCache;
    }

    public void setLookupStrategy(LookupStrategy lookupStrategy) {
        this.lookupStrategy = lookupStrategy;
    }

    protected void onTearDown() throws Exception {
        super.onTearDown();
        SecurityContextHolder.clearContext();
    }

    public void testLifecycle() {
        setComplete();

        Authentication auth = new TestingAuthenticationToken("ben", "ignored",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ADMINISTRATOR")});
        auth.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(auth);

        ObjectIdentity topParentOid = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(100));
        ObjectIdentity middleParentOid = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(101));
        ObjectIdentity childOid = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(102));

        MutableAcl topParent = jdbcMutableAclService.createAcl(topParentOid);
        MutableAcl middleParent = jdbcMutableAclService.createAcl(middleParentOid);
        MutableAcl child = jdbcMutableAclService.createAcl(childOid);

        // Specify the inheritence hierarchy
        middleParent.setParent(topParent);
        child.setParent(middleParent);

        // Now let's add a couple of permissions
        topParent.insertAce(null, BasePermission.READ, new PrincipalSid(auth), true);
        topParent.insertAce(null, BasePermission.WRITE, new PrincipalSid(auth), false);
        middleParent.insertAce(null, BasePermission.DELETE, new PrincipalSid(auth), true);
        child.insertAce(null, BasePermission.DELETE, new PrincipalSid(auth), false);

        // Explictly save the changed ACL
        jdbcMutableAclService.updateAcl(topParent);
        jdbcMutableAclService.updateAcl(middleParent);
        jdbcMutableAclService.updateAcl(child);

        // Let's check if we can read them back correctly
        Map map = jdbcMutableAclService.readAclsById(new ObjectIdentity[] {topParentOid, middleParentOid, childOid});
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
        assertEquals(2, topParent.getEntries().length);
        assertEquals(1, middleParent.getEntries().length);
        assertEquals(1, child.getEntries().length);

        // Check the retrieved rights are correct
        assertTrue(topParent.isGranted(new Permission[] {BasePermission.READ}, new Sid[] {new PrincipalSid(auth)}, false));
        assertFalse(topParent.isGranted(new Permission[] {BasePermission.WRITE}, new Sid[] {new PrincipalSid(auth)},
                false));
        assertTrue(middleParent.isGranted(new Permission[] {BasePermission.DELETE}, new Sid[] {new PrincipalSid(auth)},
                false));
        assertFalse(child.isGranted(new Permission[] {BasePermission.DELETE}, new Sid[] {new PrincipalSid(auth)}, false));

        try {
            child.isGranted(new Permission[] {BasePermission.ADMINISTRATION}, new Sid[] {new PrincipalSid(auth)}, false);
            fail("Should have thrown NotFoundException");
        } catch (NotFoundException expected) {
            assertTrue(true);
        }

        // Now check the inherited rights (when not explicitly overridden) also look OK
        assertTrue(child.isGranted(new Permission[] {BasePermission.READ}, new Sid[] {new PrincipalSid(auth)}, false));
        assertFalse(child.isGranted(new Permission[] {BasePermission.WRITE}, new Sid[] {new PrincipalSid(auth)}, false));
        assertFalse(child.isGranted(new Permission[] {BasePermission.DELETE}, new Sid[] {new PrincipalSid(auth)}, false));

        // Next change the child so it doesn't inherit permissions from above
        child.setEntriesInheriting(false);
        jdbcMutableAclService.updateAcl(child);
        child = (MutableAcl) jdbcMutableAclService.readAclById(childOid);
        assertFalse(child.isEntriesInheriting());

        // Check the child permissions no longer inherit
        assertFalse(child.isGranted(new Permission[] {BasePermission.DELETE}, new Sid[] {new PrincipalSid(auth)}, true));

        try {
            child.isGranted(new Permission[] {BasePermission.READ}, new Sid[] {new PrincipalSid(auth)}, true);
            fail("Should have thrown NotFoundException");
        } catch (NotFoundException expected) {
            assertTrue(true);
        }

        try {
            child.isGranted(new Permission[] {BasePermission.WRITE}, new Sid[] {new PrincipalSid(auth)}, true);
            fail("Should have thrown NotFoundException");
        } catch (NotFoundException expected) {
            assertTrue(true);
        }

        // Let's add an identical permission to the child, but it'll appear AFTER the current permission, so has no impact
        child.insertAce(null, BasePermission.DELETE, new PrincipalSid(auth), true);

        // Let's also add another permission to the child
        child.insertAce(null, BasePermission.CREATE, new PrincipalSid(auth), true);

        // Save the changed child
        jdbcMutableAclService.updateAcl(child);
        child = (MutableAcl) jdbcMutableAclService.readAclById(childOid);
        assertEquals(3, child.getEntries().length);

        // Output permissions
        for (int i = 0; i < child.getEntries().length; i++) {
            System.out.println(child.getEntries()[i]);
        }

        // Check the permissions are as they should be
        assertFalse(child.isGranted(new Permission[] {BasePermission.DELETE}, new Sid[] {new PrincipalSid(auth)}, true)); // as earlier permission overrode
        assertTrue(child.isGranted(new Permission[] {BasePermission.CREATE}, new Sid[] {new PrincipalSid(auth)}, true));

        // Now check the first ACE (index 0) really is DELETE for our Sid and is non-granting
        AccessControlEntry entry = child.getEntries()[0];
        assertEquals(BasePermission.DELETE.getMask(), entry.getPermission().getMask());
        assertEquals(new PrincipalSid(auth), entry.getSid());
        assertFalse(entry.isGranting());
        assertNotNull(entry.getId());

        // Now delete that first ACE
        child.deleteAce(entry.getId());

        // Save and check it worked
        child = jdbcMutableAclService.updateAcl(child);
        assertEquals(2, child.getEntries().length);
        assertTrue(child.isGranted(new Permission[] {BasePermission.DELETE}, new Sid[] {new PrincipalSid(auth)}, false));

        SecurityContextHolder.clearContext();
    }
    
/*    public void testDeleteAclAlsoDeletesChildren() throws Exception {
        ObjectIdentity topParentOid = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(100));
        ObjectIdentity middleParentOid = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(101));
        ObjectIdentity childOid = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(102));

        // Delete the mid-parent and test if the child was deleted, as well
        jdbcMutableAclService.deleteAcl(middleParentOid, true);
        
        try {
            Acl acl = jdbcMutableAclService.readAclById(middleParentOid);
            fail("It should have thrown NotFoundException");
        }
        catch (NotFoundException expected) {
            assertTrue(true);
        }
        try {
            Acl acl = jdbcMutableAclService.readAclById(childOid);
            fail("It should have thrown NotFoundException");
        }
        catch (NotFoundException expected) {
            assertTrue(true);
        }
        
        Acl acl = jdbcMutableAclService.readAclById(topParentOid);
        assertNotNull(acl);
        assertEquals(((MutableAcl) acl).getObjectIdentity(), topParentOid);
    }*/
    
    public void testConstructorRejectsNullParameters() throws Exception {
        try {
            JdbcAclService service = new JdbcMutableAclService(null, lookupStrategy, aclCache);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
        
        try {
            JdbcAclService service = new JdbcMutableAclService(this.getJdbcTemplate().getDataSource(), null, aclCache);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
        
        try {
            JdbcAclService service = new JdbcMutableAclService(this.getJdbcTemplate().getDataSource(), lookupStrategy, null);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }
    
    public void testCreateAclRejectsNullParameter() throws Exception {
        try {
            jdbcMutableAclService.createAcl(null);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }
    
    public void testCreateAclForADuplicateDomainObject() throws Exception {
        ObjectIdentity duplicateOid = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(100));
        
        // Try to add the same object second time
        try {
            jdbcMutableAclService.createAcl(duplicateOid);
            fail("It should have thrown AlreadyExistsException");
        }
        catch (AlreadyExistsException expected) {
            assertTrue(true);
        }
    }
    
    public void testDeleteAclRejectsNullParameters() throws Exception {
        try {
            jdbcMutableAclService.deleteAcl(null, true);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }
    
    public void testDeleteAclWithChildrenThrowsException() throws Exception {
        try {
            ObjectIdentity topParentOid = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(100));
            jdbcMutableAclService.deleteAcl(topParentOid, false);
            fail("It should have thrown ChildrenExistException");
        }
        catch (ChildrenExistException expected) {
            assertTrue(true);
        }
    }
    
    public void testDeleteAllAclsRemovesAclClassRecord() throws Exception {
        Authentication auth = new TestingAuthenticationToken("ben", "ignored",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ADMINISTRATOR")});
        auth.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(auth);

        ObjectIdentity topParentOid = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(100));
        
        // Remove all acls associated with a certain class type
        jdbcMutableAclService.deleteAcl(topParentOid, true);
        
        // Check the acl_class table is empty
        assertEquals(0, getJdbcTemplate().queryForList(SELECT_ALL_CLASSES, new Object[] {"org.springframework.security.TargetObject"} ).size());
    }
    
    public void testDeleteAclRemovesRowsFromDatabase() throws Exception {
        Authentication auth = new TestingAuthenticationToken("ben", "ignored",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ADMINISTRATOR")});
        auth.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(auth);

        ObjectIdentity topParentOid = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(100));
        ObjectIdentity middleParentOid = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(101));
        ObjectIdentity childOid = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(102));
        
        // Remove the child and check all related database rows were removed accordingly
        jdbcMutableAclService.deleteAcl(childOid, false);
        assertEquals(1, getJdbcTemplate().queryForList(SELECT_ALL_CLASSES, new Object[] {"org.springframework.security.TargetObject"} ).size());
        assertEquals(0, getJdbcTemplate().queryForList(SELECT_OBJECT_IDENTITY, new Object[] {new Long(102)}).size());
        assertEquals(2, getJdbcTemplate().queryForList(SELECT_ALL_OBJECT_IDENTITIES).size());
        assertEquals(3, getJdbcTemplate().queryForList(SELECT_ACL_ENTRY, new Object[] {new Long(103)} ).size());
        
        // Check the cache
        assertNull(aclCache.getFromCache(childOid));
        assertNull(aclCache.getFromCache(new Long(102)));
    }
    
/*    public void testCumulativePermissions() {
   setComplete();
   Authentication auth = new TestingAuthenticationToken("ben", "ignored", new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ADMINISTRATOR")});
   auth.setAuthenticated(true);
   SecurityContextHolder.getContext().setAuthentication(auth);

   ObjectIdentity topParentOid = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(110));
   MutableAcl topParent = jdbcMutableAclService.createAcl(topParentOid);

   // Add an ACE permission entry
   CumulativePermission cm = new CumulativePermission().set(BasePermission.READ).set(BasePermission.ADMINISTRATION);
   assertEquals(17, cm.getMask());
       topParent.insertAce(null, cm, new PrincipalSid(auth), true);
       assertEquals(1, topParent.getEntries().length);

       // Explictly save the changed ACL
       topParent = jdbcMutableAclService.updateAcl(topParent);

       // Check the mask was retrieved correctly
       assertEquals(17, topParent.getEntries()[0].getPermission().getMask());
       assertTrue(topParent.isGranted(new Permission[] {cm}, new Sid[] {new PrincipalSid(auth)}, true));

       SecurityContextHolder.clearContext();
   }
 */
}
