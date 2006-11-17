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
package org.acegisecurity.acls.jdbc;

import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;

import org.acegisecurity.acls.AccessControlEntry;
import org.acegisecurity.acls.MutableAcl;
import org.acegisecurity.acls.NotFoundException;
import org.acegisecurity.acls.Permission;
import org.acegisecurity.acls.domain.BasePermission;
import org.acegisecurity.acls.objectidentity.ObjectIdentity;
import org.acegisecurity.acls.objectidentity.ObjectIdentityImpl;
import org.acegisecurity.acls.sid.PrincipalSid;
import org.acegisecurity.acls.sid.Sid;

import org.acegisecurity.context.SecurityContextHolder;

import org.acegisecurity.providers.TestingAuthenticationToken;

import org.springframework.test.AbstractTransactionalDataSourceSpringContextTests;

import java.util.Map;


/**
 * Integration tests the ACL system using an in-memory database.
 *
 * @author Ben Alex
 * @version $Id:JdbcAclServiceTests.java 1754 2006-11-17 02:01:21Z benalex $
 */
public class JdbcAclServiceTests extends AbstractTransactionalDataSourceSpringContextTests {
    //~ Instance fields ================================================================================================

    private JdbcMutableAclService jdbcMutableAclService;

    //~ Methods ========================================================================================================

    protected String[] getConfigLocations() {
        return new String[] {"classpath:org/acegisecurity/acls/jdbc/applicationContext-test.xml"};
    }

    public void setJdbcMutableAclService(JdbcMutableAclService jdbcAclService) {
        this.jdbcMutableAclService = jdbcAclService;
    }

    public void testLifecycle() {
        setComplete();

        Authentication auth = new TestingAuthenticationToken("ben", "ignored",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ADMINISTRATOR")});
        auth.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(auth);

        ObjectIdentity topParentOid = new ObjectIdentityImpl("org.acegisecurity.TargetObject", new Long(100));
        ObjectIdentity middleParentOid = new ObjectIdentityImpl("org.acegisecurity.TargetObject", new Long(101));
        ObjectIdentity childOid = new ObjectIdentityImpl("org.acegisecurity.TargetObject", new Long(102));

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

/*    public void testCumulativePermissions() {
   setComplete();
   Authentication auth = new TestingAuthenticationToken("ben", "ignored", new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ADMINISTRATOR")});
   auth.setAuthenticated(true);
   SecurityContextHolder.getContext().setAuthentication(auth);

   ObjectIdentity topParentOid = new ObjectIdentityImpl("org.acegisecurity.TargetObject", new Long(110));
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
