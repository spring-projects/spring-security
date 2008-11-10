package org.springframework.security.acls.domain;

import static org.junit.Assert.*;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;

import org.jmock.Expectations;
import org.jmock.Mockery;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.Authentication;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.acls.AccessControlEntry;
import org.springframework.security.acls.Acl;
import org.springframework.security.acls.AlreadyExistsException;
import org.springframework.security.acls.AuditableAccessControlEntry;
import org.springframework.security.acls.AuditableAcl;
import org.springframework.security.acls.ChildrenExistException;
import org.springframework.security.acls.MutableAcl;
import org.springframework.security.acls.MutableAclService;
import org.springframework.security.acls.NotFoundException;
import org.springframework.security.acls.OwnershipAcl;
import org.springframework.security.acls.Permission;
import org.springframework.security.acls.objectidentity.ObjectIdentity;
import org.springframework.security.acls.objectidentity.ObjectIdentityImpl;
import org.springframework.security.acls.sid.GrantedAuthoritySid;
import org.springframework.security.acls.sid.PrincipalSid;
import org.springframework.security.acls.sid.Sid;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.TestingAuthenticationToken;
import org.springframework.security.util.FieldUtils;


/**
 * Tests for {@link AclImpl}.
 *
 * @author Andrei Stefan
 */
public class AclImplTests {
    Authentication auth = new TestingAuthenticationToken("johndoe", "ignored", "ROLE_ADMINISTRATOR");
    Mockery jmockCtx = new Mockery();
    AclAuthorizationStrategy mockAuthzStrategy;
    AuditLogger mockAuditLogger;
    ObjectIdentity objectIdentity = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(100));

    // ~ Methods ========================================================================================================

    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(auth);
        mockAuthzStrategy = jmockCtx.mock(AclAuthorizationStrategy.class);
        mockAuditLogger = jmockCtx.mock(AuditLogger.class);;
        jmockCtx.checking(new Expectations() {{
            ignoring(mockAuthzStrategy);
            ignoring(mockAuditLogger);
        }});
        auth.setAuthenticated(true);
    }

    @After
    public void tearDown() throws Exception {
        SecurityContextHolder.clearContext();
    }

    @Test(expected=IllegalArgumentException.class)
    public void testConstructorsRejectNullObjectIdentity() throws Exception {
        try {
            new AclImpl(null, new Long(1), mockAuthzStrategy, mockAuditLogger, null, null, true, new PrincipalSid("johndoe"));
            fail("Should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
        }
        new AclImpl(null, new Long(1), mockAuthzStrategy, mockAuditLogger);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testConstructorsRejectNullId() throws Exception {
        try {
            new AclImpl(objectIdentity, null, mockAuthzStrategy, mockAuditLogger, null, null, true, new PrincipalSid("johndoe"));
            fail("Should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
        }
        new AclImpl(objectIdentity, null, mockAuthzStrategy, mockAuditLogger);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testConstructorsRejectNullAclAuthzStrategy() throws Exception {
        try {
            new AclImpl(objectIdentity, new Long(1), null, mockAuditLogger, null, null, true, new PrincipalSid("johndoe"));
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
        }
        new AclImpl(objectIdentity, new Long(1), null, mockAuditLogger);
    }

    @Test(expected=IllegalArgumentException.class)
    public void testConstructorsRejectNullAuditLogger() throws Exception {
        try {
            new AclImpl(objectIdentity, new Long(1), mockAuthzStrategy, null, null, null, true, new PrincipalSid("johndoe"));
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
        }
        new AclImpl(objectIdentity, new Long(1), mockAuthzStrategy, null);
    }

    @Test
    public void testInsertAceRejectsNullParameters() throws Exception {
        MutableAcl acl = new AclImpl(objectIdentity, new Long(1), mockAuthzStrategy, mockAuditLogger, null, null, true, new PrincipalSid(
                "johndoe"));
        try {
            acl.insertAce(0, null, new GrantedAuthoritySid("ROLE_IGNORED"), true);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
        }
        try {
            acl.insertAce(0, BasePermission.READ, null, true);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testInsertAceAddsElementAtCorrectIndex() throws Exception {
        MutableAcl acl = new AclImpl(objectIdentity, new Long(1), mockAuthzStrategy, mockAuditLogger, null, null, true, new PrincipalSid("johndoe"));
        MockAclService service = new MockAclService();

        // Insert one permission
        acl.insertAce(0, BasePermission.READ, new GrantedAuthoritySid("ROLE_TEST1"), true);
        service.updateAcl(acl);
        // Check it was successfully added
        assertEquals(1, acl.getEntries().length);
        assertEquals(acl.getEntries()[0].getAcl(), acl);
        assertEquals(acl.getEntries()[0].getPermission(), BasePermission.READ);
        assertEquals(acl.getEntries()[0].getSid(), new GrantedAuthoritySid("ROLE_TEST1"));

        // Add a second permission
        acl.insertAce(1, BasePermission.READ, new GrantedAuthoritySid("ROLE_TEST2"), true);
        service.updateAcl(acl);
        // Check it was added on the last position
        assertEquals(2, acl.getEntries().length);
        assertEquals(acl.getEntries()[1].getAcl(), acl);
        assertEquals(acl.getEntries()[1].getPermission(), BasePermission.READ);
        assertEquals(acl.getEntries()[1].getSid(), new GrantedAuthoritySid("ROLE_TEST2"));

        // Add a third permission, after the first one
        acl.insertAce(1, BasePermission.WRITE, new GrantedAuthoritySid("ROLE_TEST3"), false);
        service.updateAcl(acl);
        assertEquals(3, acl.getEntries().length);
        // Check the third entry was added between the two existent ones
        assertEquals(acl.getEntries()[0].getPermission(), BasePermission.READ);
        assertEquals(acl.getEntries()[0].getSid(), new GrantedAuthoritySid("ROLE_TEST1"));
        assertEquals(acl.getEntries()[1].getPermission(), BasePermission.WRITE);
        assertEquals(acl.getEntries()[1].getSid(), new GrantedAuthoritySid("ROLE_TEST3"));
        assertEquals(acl.getEntries()[2].getPermission(), BasePermission.READ);
        assertEquals(acl.getEntries()[2].getSid(), new GrantedAuthoritySid("ROLE_TEST2"));
    }

    @Test(expected=NotFoundException.class)
    public void testInsertAceFailsForInexistentElement() throws Exception {
        MutableAcl acl = new AclImpl(objectIdentity, new Long(1), mockAuthzStrategy, mockAuditLogger, null, null, true, new PrincipalSid(
                "johndoe"));
        MockAclService service = new MockAclService();

        // Insert one permission
        acl.insertAce(0, BasePermission.READ, new GrantedAuthoritySid("ROLE_TEST1"), true);
        service.updateAcl(acl);

        acl.insertAce(55, BasePermission.READ, new GrantedAuthoritySid("ROLE_TEST2"), true);
    }

    @Test
    public void testDeleteAceKeepsInitialOrdering() throws Exception {
        MutableAcl acl = new AclImpl(objectIdentity, new Long(1), mockAuthzStrategy, mockAuditLogger, null, null, true, new PrincipalSid(
                "johndoe"));
        MockAclService service = new MockAclService();

        // Add several permissions
        acl.insertAce(0, BasePermission.READ, new GrantedAuthoritySid("ROLE_TEST1"), true);
        acl.insertAce(1, BasePermission.READ, new GrantedAuthoritySid("ROLE_TEST2"), true);
        acl.insertAce(2, BasePermission.READ, new GrantedAuthoritySid("ROLE_TEST3"), true);
        service.updateAcl(acl);

        // Delete first permission and check the order of the remaining permissions is kept
        acl.deleteAce(0);
        assertEquals(2, acl.getEntries().length);
        assertEquals(acl.getEntries()[0].getSid(), new GrantedAuthoritySid("ROLE_TEST2"));
        assertEquals(acl.getEntries()[1].getSid(), new GrantedAuthoritySid("ROLE_TEST3"));

        // Add one more permission and remove the permission in the middle
        acl.insertAce(2, BasePermission.READ, new GrantedAuthoritySid("ROLE_TEST4"), true);
        service.updateAcl(acl);
        acl.deleteAce(1);
        assertEquals(2, acl.getEntries().length);
        assertEquals(acl.getEntries()[0].getSid(), new GrantedAuthoritySid("ROLE_TEST2"));
        assertEquals(acl.getEntries()[1].getSid(), new GrantedAuthoritySid("ROLE_TEST4"));

        // Remove remaining permissions
        acl.deleteAce(1);
        acl.deleteAce(0);
        assertEquals(0, acl.getEntries().length);
    }

    @Test
    public void testDeleteAceFailsForInexistentElement() throws Exception {
        AclAuthorizationStrategyImpl strategy = new AclAuthorizationStrategyImpl(new GrantedAuthority[] {
                new GrantedAuthorityImpl("ROLE_OWNERSHIP"), new GrantedAuthorityImpl("ROLE_AUDITING"),
                new GrantedAuthorityImpl("ROLE_GENERAL") });
        AuditLogger auditLogger = new ConsoleAuditLogger();
        MutableAcl acl = new AclImpl(objectIdentity, new Long(1), strategy, auditLogger, null, null, true, new PrincipalSid(
                "johndoe"));
        try {
            acl.deleteAce(99);
            fail("It should have thrown NotFoundException");
        }
        catch (NotFoundException expected) {
        }
    }

    @Test
    public void testIsGrantingRejectsEmptyParameters() throws Exception {
        MutableAcl acl = new AclImpl(objectIdentity, new Long(1), mockAuthzStrategy, mockAuditLogger, null, null, true, new PrincipalSid(
                "johndoe"));
        try {
            acl.isGranted(new Permission[] {}, new Sid[] { new PrincipalSid("ben") }, false);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
        }
        try {
            acl.isGranted(new Permission[] { BasePermission.READ }, new Sid[] {}, false);
            fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testIsGrantingGrantsAccessForAclWithNoParent() throws Exception {
        Authentication auth = new TestingAuthenticationToken("ben", "ignored", "ROLE_GENERAL","ROLE_GUEST");
        auth.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(auth);
        ObjectIdentity rootOid = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(100));

        // Create an ACL which owner is not the authenticated principal
        MutableAcl rootAcl = new AclImpl(rootOid, new Long(1), mockAuthzStrategy, mockAuditLogger, null, null, false, new PrincipalSid(
                "johndoe"));

        // Grant some permissions
        rootAcl.insertAce(0, BasePermission.READ, new PrincipalSid("ben"), false);
        rootAcl.insertAce(1, BasePermission.WRITE, new PrincipalSid("scott"), true);
        rootAcl.insertAce(2, BasePermission.WRITE, new PrincipalSid("rod"), false);
        rootAcl.insertAce(3, BasePermission.WRITE, new GrantedAuthoritySid("WRITE_ACCESS_ROLE"), true);

        // Check permissions granting
        Permission[] permissions = new Permission[] { BasePermission.READ, BasePermission.CREATE };
        Sid[] sids = new Sid[] { new PrincipalSid("ben"), new GrantedAuthoritySid("ROLE_GUEST") };
        assertFalse(rootAcl.isGranted(permissions, sids, false));
        try {
            rootAcl.isGranted(permissions, new Sid[] { new PrincipalSid("scott") }, false);
            fail("It should have thrown NotFoundException");
        }
        catch (NotFoundException expected) {
        }
        assertTrue(rootAcl.isGranted(new Permission[] { BasePermission.WRITE }, new Sid[] { new PrincipalSid("scott") },
                false));
        assertFalse(rootAcl.isGranted(new Permission[] { BasePermission.WRITE }, new Sid[] { new PrincipalSid("rod"),
                new GrantedAuthoritySid("WRITE_ACCESS_ROLE") }, false));
        assertTrue(rootAcl.isGranted(new Permission[] { BasePermission.WRITE }, new Sid[] {
                new GrantedAuthoritySid("WRITE_ACCESS_ROLE"), new PrincipalSid("rod") }, false));
        try {
            // Change the type of the Sid and check the granting process
            rootAcl.isGranted(new Permission[] { BasePermission.WRITE }, new Sid[] { new GrantedAuthoritySid("rod"),
                    new PrincipalSid("WRITE_ACCESS_ROLE") }, false);
            fail("It should have thrown NotFoundException");
        }
        catch (NotFoundException expected) {
        }
    }

    @Test
    public void testIsGrantingGrantsAccessForInheritableAcls() throws Exception {
        Authentication auth = new TestingAuthenticationToken("ben", "ignored","ROLE_GENERAL");
        auth.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(auth);
        ObjectIdentity grandParentOid = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(100));
        ObjectIdentity parentOid1 = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(101));
        ObjectIdentity parentOid2 = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(102));
        ObjectIdentity childOid1 = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(103));
        ObjectIdentity childOid2 = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(104));

        // Create ACLs
        MutableAcl grandParentAcl = new AclImpl(grandParentOid, new Long(1), mockAuthzStrategy, mockAuditLogger, null, null, false,
                new PrincipalSid("johndoe"));
        MutableAcl parentAcl1 = new AclImpl(parentOid1, new Long(2), mockAuthzStrategy, mockAuditLogger, null, null, true,
                new PrincipalSid("johndoe"));
        MutableAcl parentAcl2 = new AclImpl(parentOid2, new Long(3), mockAuthzStrategy, mockAuditLogger, null, null, true,
                new PrincipalSid("johndoe"));
        MutableAcl childAcl1 = new AclImpl(childOid1, new Long(4), mockAuthzStrategy, mockAuditLogger, null, null, true,
                new PrincipalSid("johndoe"));
        MutableAcl childAcl2 = new AclImpl(childOid2, new Long(4), mockAuthzStrategy, mockAuditLogger, null, null, false,
                new PrincipalSid("johndoe"));

        // Create hierarchies
        childAcl2.setParent(childAcl1);
        childAcl1.setParent(parentAcl1);
        parentAcl2.setParent(grandParentAcl);
        parentAcl1.setParent(grandParentAcl);

        // Add some permissions
        grandParentAcl.insertAce(0, BasePermission.READ, new GrantedAuthoritySid("ROLE_USER_READ"), true);
        grandParentAcl.insertAce(1, BasePermission.WRITE, new PrincipalSid("ben"), true);
        grandParentAcl.insertAce(2, BasePermission.DELETE, new PrincipalSid("ben"), false);
        grandParentAcl.insertAce(3, BasePermission.DELETE, new PrincipalSid("scott"), true);
        parentAcl1.insertAce(0, BasePermission.READ, new PrincipalSid("scott"), true);
        parentAcl1.insertAce(1, BasePermission.DELETE, new PrincipalSid("scott"), false);
        parentAcl2.insertAce(0, BasePermission.CREATE, new PrincipalSid("ben"), true);
        childAcl1.insertAce(0, BasePermission.CREATE, new PrincipalSid("scott"), true);

        // Check granting process for parent1
        assertTrue(parentAcl1.isGranted(new Permission[] { BasePermission.READ }, new Sid[] { new PrincipalSid("scott") },
                false));
        assertTrue(parentAcl1.isGranted(new Permission[] { BasePermission.READ }, new Sid[] { new GrantedAuthoritySid(
                "ROLE_USER_READ") }, false));
        assertTrue(parentAcl1.isGranted(new Permission[] { BasePermission.WRITE }, new Sid[] { new PrincipalSid("ben") },
                false));
        assertFalse(parentAcl1.isGranted(new Permission[] { BasePermission.DELETE }, new Sid[] { new PrincipalSid("ben") },
                false));
        assertFalse(parentAcl1.isGranted(new Permission[] { BasePermission.DELETE },
                new Sid[] { new PrincipalSid("scott") }, false));

        // Check granting process for parent2
        assertTrue(parentAcl2.isGranted(new Permission[] { BasePermission.CREATE }, new Sid[] { new PrincipalSid("ben") },
                false));
        assertTrue(parentAcl2.isGranted(new Permission[] { BasePermission.WRITE }, new Sid[] { new PrincipalSid("ben") },
                false));
        assertFalse(parentAcl2.isGranted(new Permission[] { BasePermission.DELETE }, new Sid[] { new PrincipalSid("ben") },
                false));

        // Check granting process for child1
        assertTrue(childAcl1.isGranted(new Permission[] { BasePermission.CREATE }, new Sid[] { new PrincipalSid("scott") },
                false));
        assertTrue(childAcl1.isGranted(new Permission[] { BasePermission.READ }, new Sid[] { new GrantedAuthoritySid(
                "ROLE_USER_READ") }, false));
        assertFalse(childAcl1.isGranted(new Permission[] { BasePermission.DELETE }, new Sid[] { new PrincipalSid("ben") },
                false));

        // Check granting process for child2 (doesn't inherit the permissions from its parent)
        try {
            assertTrue(childAcl2.isGranted(new Permission[] { BasePermission.CREATE },
                    new Sid[] { new PrincipalSid("scott") }, false));
            fail("It should have thrown NotFoundException");
        }
        catch (NotFoundException expected) {
            assertTrue(true);
        }
        try {
            assertTrue(childAcl2.isGranted(new Permission[] { BasePermission.CREATE }, new Sid[] { new PrincipalSid(
                    "johndoe") }, false));
            fail("It should have thrown NotFoundException");
        }
        catch (NotFoundException expected) {
            assertTrue(true);
        }
    }

    @Test
    public void testUpdateAce() throws Exception {
        Authentication auth = new TestingAuthenticationToken("ben", "ignored","ROLE_GENERAL");
        auth.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(auth);
        MutableAcl acl = new AclImpl(objectIdentity, new Long(1), mockAuthzStrategy, mockAuditLogger, null, null, false, new PrincipalSid(
                "johndoe"));
        MockAclService service = new MockAclService();

        acl.insertAce(0, BasePermission.READ, new GrantedAuthoritySid("ROLE_USER_READ"), true);
        acl.insertAce(1, BasePermission.WRITE, new GrantedAuthoritySid("ROLE_USER_READ"), true);
        acl.insertAce(2, BasePermission.CREATE, new PrincipalSid("ben"), true);
        service.updateAcl(acl);

        assertEquals(acl.getEntries()[0].getPermission(), BasePermission.READ);
        assertEquals(acl.getEntries()[1].getPermission(), BasePermission.WRITE);
        assertEquals(acl.getEntries()[2].getPermission(), BasePermission.CREATE);

        // Change each permission
        acl.updateAce(0, BasePermission.CREATE);
        acl.updateAce(1, BasePermission.DELETE);
        acl.updateAce(2, BasePermission.READ);

        // Check the change was successfuly made
        assertEquals(acl.getEntries()[0].getPermission(), BasePermission.CREATE);
        assertEquals(acl.getEntries()[1].getPermission(), BasePermission.DELETE);
        assertEquals(acl.getEntries()[2].getPermission(), BasePermission.READ);
    }

    @Test
    public void testUpdateAuditing() throws Exception {
        Authentication auth = new TestingAuthenticationToken("ben", "ignored", "ROLE_AUDITING", "ROLE_GENERAL");
        auth.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(auth);
        MutableAcl acl = new AclImpl(objectIdentity, new Long(1), mockAuthzStrategy, mockAuditLogger, null, null, false, new PrincipalSid(
                "johndoe"));
        MockAclService service = new MockAclService();

        acl.insertAce(0, BasePermission.READ, new GrantedAuthoritySid("ROLE_USER_READ"), true);
        acl.insertAce(1, BasePermission.WRITE, new GrantedAuthoritySid("ROLE_USER_READ"), true);
        service.updateAcl(acl);

        assertFalse(((AuditableAccessControlEntry) acl.getEntries()[0]).isAuditFailure());
        assertFalse(((AuditableAccessControlEntry) acl.getEntries()[1]).isAuditFailure());
        assertFalse(((AuditableAccessControlEntry) acl.getEntries()[0]).isAuditSuccess());
        assertFalse(((AuditableAccessControlEntry) acl.getEntries()[1]).isAuditSuccess());

        // Change each permission
        ((AuditableAcl) acl).updateAuditing(0, true, true);
        ((AuditableAcl) acl).updateAuditing(1, true, true);

        // Check the change was successfuly made
        assertTrue(((AuditableAccessControlEntry) acl.getEntries()[0]).isAuditFailure());
        assertTrue(((AuditableAccessControlEntry) acl.getEntries()[1]).isAuditFailure());
        assertTrue(((AuditableAccessControlEntry) acl.getEntries()[0]).isAuditSuccess());
        assertTrue(((AuditableAccessControlEntry) acl.getEntries()[1]).isAuditSuccess());
    }

    @Test
    public void testGettersSetters() throws Exception {
        Authentication auth = new TestingAuthenticationToken("ben", "ignored", new GrantedAuthority[] {
                new GrantedAuthorityImpl("ROLE_GENERAL") });
        auth.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(auth);
        ObjectIdentity identity = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(100));
        ObjectIdentity identity2 = new ObjectIdentityImpl("org.springframework.security.TargetObject", new Long(101));
        MutableAcl acl = new AclImpl(identity, new Long(1), mockAuthzStrategy, mockAuditLogger, null, null, true, new PrincipalSid(
                "johndoe"));
        MutableAcl parentAcl = new AclImpl(identity2, new Long(2), mockAuthzStrategy, mockAuditLogger, null, null, true, new PrincipalSid(
                "johndoe"));
        MockAclService service = new MockAclService();
        acl.insertAce(0, BasePermission.READ, new GrantedAuthoritySid("ROLE_USER_READ"), true);
        acl.insertAce(1, BasePermission.WRITE, new GrantedAuthoritySid("ROLE_USER_READ"), true);
        service.updateAcl(acl);

        assertEquals(acl.getId(), new Long(1));
        assertEquals(acl.getObjectIdentity(), identity);
        assertEquals(acl.getOwner(), new PrincipalSid("johndoe"));
        assertNull(acl.getParentAcl());
        assertTrue(acl.isEntriesInheriting());
        assertEquals(2, acl.getEntries().length);

        acl.setParent(parentAcl);
        assertEquals(acl.getParentAcl(), parentAcl);

        acl.setEntriesInheriting(false);
        assertFalse(acl.isEntriesInheriting());

        ((OwnershipAcl) acl).setOwner(new PrincipalSid("ben"));
        assertEquals(acl.getOwner(), new PrincipalSid("ben"));
    }

    @Test
    public void testIsSidLoaded() throws Exception {
        Sid[] loadedSids = new Sid[] { new PrincipalSid("ben"), new GrantedAuthoritySid("ROLE_IGNORED") };
        MutableAcl acl = new AclImpl(objectIdentity, new Long(1), mockAuthzStrategy, mockAuditLogger, null, loadedSids, true, new PrincipalSid(
                "johndoe"));

        assertTrue(acl.isSidLoaded(loadedSids));
        assertTrue(acl.isSidLoaded(new Sid[] { new GrantedAuthoritySid("ROLE_IGNORED"), new PrincipalSid("ben") }));
        assertTrue(acl.isSidLoaded(new Sid[] { new GrantedAuthoritySid("ROLE_IGNORED")}));
        assertTrue(acl.isSidLoaded(new Sid[] { new PrincipalSid("ben") }));
        assertTrue(acl.isSidLoaded(null));
        assertTrue(acl.isSidLoaded(new Sid[] { }));
        assertTrue(acl.isSidLoaded(new Sid[] { new GrantedAuthoritySid("ROLE_IGNORED"), new GrantedAuthoritySid("ROLE_IGNORED") }));
        assertFalse(acl.isSidLoaded(new Sid[] { new GrantedAuthoritySid("ROLE_GENERAL"), new GrantedAuthoritySid("ROLE_IGNORED") }));
        assertFalse(acl.isSidLoaded(new Sid[] { new GrantedAuthoritySid("ROLE_IGNORED"), new GrantedAuthoritySid("ROLE_GENERAL") }));
    }

    //~ Inner Classes ==================================================================================================

    private class MockAclService implements MutableAclService {
        public MutableAcl createAcl(ObjectIdentity objectIdentity) throws AlreadyExistsException {
            return null;
        }

        public void deleteAcl(ObjectIdentity objectIdentity, boolean deleteChildren) throws ChildrenExistException {
        }

        /*
         * Mock implementation that populates the aces list with fully initialized AccessControlEntries
         * @see org.springframework.security.acls.MutableAclService#updateAcl(org.springframework.security.acls.MutableAcl)
         */
        public MutableAcl updateAcl(MutableAcl acl) throws NotFoundException {
            AccessControlEntry[] oldAces = acl.getEntries();
            Field acesField = FieldUtils.getField(AclImpl.class, "aces");
            acesField.setAccessible(true);
            List newAces;
            try {
                newAces = (List) acesField.get(acl);
                newAces.clear();

                for (int i = 0; i < oldAces.length; i++) {
                    AccessControlEntry ac = oldAces[i];
                    // Just give an ID to all this acl's aces, rest of the fields are just copied
                    newAces.add(new AccessControlEntryImpl(new Long(i + 1), ac.getAcl(), ac.getSid(), ac.getPermission(), ac
                            .isGranting(), ((AuditableAccessControlEntry) ac).isAuditSuccess(),
                            ((AuditableAccessControlEntry) ac).isAuditFailure()));
                }
            }
            catch (IllegalAccessException e) {
                e.printStackTrace();
            }

            return acl;
        }

        public ObjectIdentity[] findChildren(ObjectIdentity parentIdentity) {
            return null;
        }

        public Acl readAclById(ObjectIdentity object) throws NotFoundException {
            return null;
        }

        public Acl readAclById(ObjectIdentity object, Sid[] sids) throws NotFoundException {
            return null;
        }

        public Map readAclsById(ObjectIdentity[] objects) throws NotFoundException {
            return null;
        }

        public Map readAclsById(ObjectIdentity[] objects, Sid[] sids) throws NotFoundException {
            return null;
        }
    }
}
