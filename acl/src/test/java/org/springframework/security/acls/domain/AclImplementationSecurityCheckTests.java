package org.springframework.security.acls.domain;

import junit.framework.Assert;
import junit.framework.TestCase;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.acls.Acl;
import org.springframework.security.acls.MutableAcl;
import org.springframework.security.acls.NotFoundException;
import org.springframework.security.acls.objectidentity.ObjectIdentity;
import org.springframework.security.acls.objectidentity.ObjectIdentityImpl;
import org.springframework.security.acls.sid.PrincipalSid;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Test class for {@link AclAuthorizationStrategyImpl} and {@link AclImpl}
 * security checks.
 *
 * @author Andrei Stefan
 */
public class AclImplementationSecurityCheckTests extends TestCase {
    private static final String TARGET_CLASS = "org.springframework.security.acls.TargetObject";

    //~ Methods ========================================================================================================

    protected void setUp() throws Exception {
        SecurityContextHolder.clearContext();
    }

    protected void tearDown() throws Exception {
        SecurityContextHolder.clearContext();
    }

    public void testSecurityCheckNoACEs() throws Exception {
        Authentication auth = new TestingAuthenticationToken("user", "password","ROLE_GENERAL","ROLE_AUDITING","ROLE_OWNERSHIP");
        auth.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(auth);

        ObjectIdentity identity = new ObjectIdentityImpl(TARGET_CLASS, new Long(100));
        AclAuthorizationStrategy aclAuthorizationStrategy = new AclAuthorizationStrategyImpl(new GrantedAuthority[] {
                new GrantedAuthorityImpl("ROLE_OWNERSHIP"), new GrantedAuthorityImpl("ROLE_AUDITING"),
                new GrantedAuthorityImpl("ROLE_GENERAL") });

        Acl acl = new AclImpl(identity, new Long(1), aclAuthorizationStrategy, new ConsoleAuditLogger());

        aclAuthorizationStrategy.securityCheck(acl, AclAuthorizationStrategy.CHANGE_GENERAL);
        aclAuthorizationStrategy.securityCheck(acl, AclAuthorizationStrategy.CHANGE_AUDITING);
        aclAuthorizationStrategy.securityCheck(acl, AclAuthorizationStrategy.CHANGE_OWNERSHIP);

        // Create another authorization strategy
        AclAuthorizationStrategy aclAuthorizationStrategy2 = new AclAuthorizationStrategyImpl(new GrantedAuthority[] {
                new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO"),
                new GrantedAuthorityImpl("ROLE_THREE") });
        Acl acl2 = new AclImpl(identity, new Long(1), aclAuthorizationStrategy2, new ConsoleAuditLogger());
        // Check access in case the principal has no authorization rights
        try {
            aclAuthorizationStrategy2.securityCheck(acl2, AclAuthorizationStrategy.CHANGE_GENERAL);
            Assert.fail("It should have thrown NotFoundException");
        }
        catch (NotFoundException expected) {
        }
        try {
            aclAuthorizationStrategy2.securityCheck(acl2, AclAuthorizationStrategy.CHANGE_AUDITING);
            Assert.fail("It should have thrown NotFoundException");
        }
        catch (NotFoundException expected) {
        }
        try {
            aclAuthorizationStrategy2.securityCheck(acl2, AclAuthorizationStrategy.CHANGE_OWNERSHIP);
            Assert.fail("It should have thrown NotFoundException");
        }
        catch (NotFoundException expected) {
        }
    }

    public void testSecurityCheckWithMultipleACEs() throws Exception {
        // Create a simple authentication with ROLE_GENERAL
        Authentication auth = new TestingAuthenticationToken("user", "password",
                new GrantedAuthority[] { new GrantedAuthorityImpl("ROLE_GENERAL") });
        auth.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(auth);

        ObjectIdentity identity = new ObjectIdentityImpl(TARGET_CLASS, new Long(100));
        // Authorization strategy will require a different role for each access
        AclAuthorizationStrategy aclAuthorizationStrategy = new AclAuthorizationStrategyImpl(new GrantedAuthority[] {
                new GrantedAuthorityImpl("ROLE_OWNERSHIP"), new GrantedAuthorityImpl("ROLE_AUDITING"),
                new GrantedAuthorityImpl("ROLE_GENERAL") });

        // Let's give the principal the ADMINISTRATION permission, without
        // granting access
        MutableAcl aclFirstDeny = new AclImpl(identity, new Long(1), aclAuthorizationStrategy, new ConsoleAuditLogger());
        aclFirstDeny.insertAce(0, BasePermission.ADMINISTRATION, new PrincipalSid(auth), false);

        // The CHANGE_GENERAL test should pass as the principal has ROLE_GENERAL
        aclAuthorizationStrategy.securityCheck(aclFirstDeny, AclAuthorizationStrategy.CHANGE_GENERAL);

        // The CHANGE_AUDITING and CHANGE_OWNERSHIP should fail since the
        // principal doesn't have these authorities,
        // nor granting access
        try {
            aclAuthorizationStrategy.securityCheck(aclFirstDeny, AclAuthorizationStrategy.CHANGE_AUDITING);
            Assert.fail("It should have thrown AccessDeniedException");
        }
        catch (AccessDeniedException expected) {
        }
        try {
            aclAuthorizationStrategy.securityCheck(aclFirstDeny, AclAuthorizationStrategy.CHANGE_OWNERSHIP);
            Assert.fail("It should have thrown AccessDeniedException");
        }
        catch (AccessDeniedException expected) {
        }

        // Add granting access to this principal
        aclFirstDeny.insertAce(1, BasePermission.ADMINISTRATION, new PrincipalSid(auth), true);
        // and try again for CHANGE_AUDITING - the first ACE's granting flag
        // (false) will deny this access
        try {
            aclAuthorizationStrategy.securityCheck(aclFirstDeny, AclAuthorizationStrategy.CHANGE_AUDITING);
            Assert.fail("It should have thrown AccessDeniedException");
        }
        catch (AccessDeniedException expected) {
        }

        // Create another ACL and give the principal the ADMINISTRATION
        // permission, with granting access
        MutableAcl aclFirstAllow = new AclImpl(identity, new Long(1), aclAuthorizationStrategy,
                new ConsoleAuditLogger());
        aclFirstAllow.insertAce(0, BasePermission.ADMINISTRATION, new PrincipalSid(auth), true);

        // The CHANGE_AUDITING test should pass as there is one ACE with
        // granting access

        aclAuthorizationStrategy.securityCheck(aclFirstAllow, AclAuthorizationStrategy.CHANGE_AUDITING);

        // Add a deny ACE and test again for CHANGE_AUDITING
        aclFirstAllow.insertAce(1, BasePermission.ADMINISTRATION, new PrincipalSid(auth), false);
        try {
            aclAuthorizationStrategy.securityCheck(aclFirstAllow, AclAuthorizationStrategy.CHANGE_AUDITING);
            Assert.assertTrue(true);
        }
        catch (AccessDeniedException notExpected) {
            Assert.fail("It shouldn't have thrown AccessDeniedException");
        }

        // Create an ACL with no ACE
        MutableAcl aclNoACE = new AclImpl(identity, new Long(1), aclAuthorizationStrategy, new ConsoleAuditLogger());
        try {
            aclAuthorizationStrategy.securityCheck(aclNoACE, AclAuthorizationStrategy.CHANGE_AUDITING);
            Assert.fail("It should have thrown NotFoundException");
        }
        catch (NotFoundException expected) {
            Assert.assertTrue(true);
        }
        // and still grant access for CHANGE_GENERAL
        try {
            aclAuthorizationStrategy.securityCheck(aclNoACE, AclAuthorizationStrategy.CHANGE_GENERAL);
            Assert.assertTrue(true);
        }
        catch (NotFoundException expected) {
            Assert.fail("It shouldn't have thrown NotFoundException");
        }
    }

    public void testSecurityCheckWithInheritableACEs() throws Exception {
        // Create a simple authentication with ROLE_GENERAL
        Authentication auth = new TestingAuthenticationToken("user", "password",
                new GrantedAuthority[] { new GrantedAuthorityImpl("ROLE_GENERAL") });
        auth.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(auth);

        ObjectIdentity identity = new ObjectIdentityImpl(TARGET_CLASS, new Long(100));
        // Authorization strategy will require a different role for each access
        AclAuthorizationStrategy aclAuthorizationStrategy = new AclAuthorizationStrategyImpl(new GrantedAuthority[] {
                new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO"),
                new GrantedAuthorityImpl("ROLE_GENERAL") });

        // Let's give the principal an ADMINISTRATION permission, with granting
        // access
        MutableAcl parentAcl = new AclImpl(identity, new Long(1), aclAuthorizationStrategy, new ConsoleAuditLogger());
        parentAcl.insertAce(0, BasePermission.ADMINISTRATION, new PrincipalSid(auth), true);
        MutableAcl childAcl = new AclImpl(identity, new Long(2), aclAuthorizationStrategy, new ConsoleAuditLogger());

        // Check against the 'child' acl, which doesn't offer any authorization
        // rights on CHANGE_OWNERSHIP
        try {
            aclAuthorizationStrategy.securityCheck(childAcl, AclAuthorizationStrategy.CHANGE_OWNERSHIP);
            Assert.fail("It should have thrown NotFoundException");
        }
        catch (NotFoundException expected) {
            Assert.assertTrue(true);
        }

        // Link the child with its parent and test again against the
        // CHANGE_OWNERSHIP right
        childAcl.setParent(parentAcl);
        childAcl.setEntriesInheriting(true);
        try {
            aclAuthorizationStrategy.securityCheck(childAcl, AclAuthorizationStrategy.CHANGE_OWNERSHIP);
            Assert.assertTrue(true);
        }
        catch (NotFoundException expected) {
            Assert.fail("It shouldn't have thrown NotFoundException");
        }

        // Create a root parent and link it to the middle parent
        MutableAcl rootParentAcl = new AclImpl(identity, new Long(1), aclAuthorizationStrategy,
                new ConsoleAuditLogger());
        parentAcl = new AclImpl(identity, new Long(1), aclAuthorizationStrategy, new ConsoleAuditLogger());
        rootParentAcl.insertAce(0, BasePermission.ADMINISTRATION, new PrincipalSid(auth), true);
        parentAcl.setEntriesInheriting(true);
        parentAcl.setParent(rootParentAcl);
        childAcl.setParent(parentAcl);
        try {
            aclAuthorizationStrategy.securityCheck(childAcl, AclAuthorizationStrategy.CHANGE_OWNERSHIP);
            Assert.assertTrue(true);
        }
        catch (NotFoundException expected) {
            Assert.fail("It shouldn't have thrown NotFoundException");
        }
    }

    public void testSecurityCheckPrincipalOwner() throws Exception {
        Authentication auth = new TestingAuthenticationToken("user", "password", new GrantedAuthority[] {
                new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_ONE"),
                new GrantedAuthorityImpl("ROLE_ONE") });
        auth.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(auth);

        ObjectIdentity identity = new ObjectIdentityImpl(TARGET_CLASS, new Long(100));
        AclAuthorizationStrategy aclAuthorizationStrategy = new AclAuthorizationStrategyImpl(new GrantedAuthority[] {
                new GrantedAuthorityImpl("ROLE_OWNERSHIP"), new GrantedAuthorityImpl("ROLE_AUDITING"),
                new GrantedAuthorityImpl("ROLE_GENERAL") });

        Acl acl = new AclImpl(identity, new Long(1), aclAuthorizationStrategy, new ConsoleAuditLogger(), null, null,
                false, new PrincipalSid(auth));
        try {
            aclAuthorizationStrategy.securityCheck(acl, AclAuthorizationStrategy.CHANGE_GENERAL);
            Assert.assertTrue(true);
        }
        catch (AccessDeniedException notExpected) {
            Assert.fail("It shouldn't have thrown AccessDeniedException");
        }
        try {
            aclAuthorizationStrategy.securityCheck(acl, AclAuthorizationStrategy.CHANGE_AUDITING);
            Assert.fail("It shouldn't have thrown AccessDeniedException");
        }
        catch (NotFoundException expected) {
            Assert.assertTrue(true);
        }
        try {
            aclAuthorizationStrategy.securityCheck(acl, AclAuthorizationStrategy.CHANGE_OWNERSHIP);
            Assert.assertTrue(true);
        }
        catch (AccessDeniedException notExpected) {
            Assert.fail("It shouldn't have thrown AccessDeniedException");
        }
    }
}
