package org.springframework.security.acls.sid;

import junit.framework.Assert;
import junit.framework.TestCase;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class SidTests extends TestCase {

    //~ Methods ========================================================================================================

    public void testPrincipalSidConstructorsRequiredFields() throws Exception {
        // Check one String-argument constructor
        try {
            String string = null;
            new PrincipalSid(string);
            Assert.fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
            Assert.assertTrue(true);
        }

        try {
            new PrincipalSid("");
            Assert.fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
            Assert.assertTrue(true);
        }

        try {
            new PrincipalSid("johndoe");
            Assert.assertTrue(true);
        }
        catch (IllegalArgumentException notExpected) {
            Assert.fail("It shouldn't have thrown IllegalArgumentException");
        }

        // Check one Authentication-argument constructor
        try {
            Authentication authentication = null;
            new PrincipalSid(authentication);
            Assert.fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
            Assert.assertTrue(true);
        }

        try {
            Authentication authentication = new TestingAuthenticationToken(null, "password");
            new PrincipalSid(authentication);
            Assert.fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
            Assert.assertTrue(true);
        }

        try {
            Authentication authentication = new TestingAuthenticationToken("johndoe", "password");
            new PrincipalSid(authentication);
            Assert.assertTrue(true);
        }
        catch (IllegalArgumentException notExpected) {
            Assert.fail("It shouldn't have thrown IllegalArgumentException");
        }
    }

    public void testGrantedAuthoritySidConstructorsRequiredFields() throws Exception {
        // Check one String-argument constructor
        try {
            String string = null;
            new GrantedAuthoritySid(string);
            Assert.fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
            Assert.assertTrue(true);
        }

        try {
            new GrantedAuthoritySid("");
            Assert.fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
            Assert.assertTrue(true);
        }

        try {
            new GrantedAuthoritySid("ROLE_TEST");
            Assert.assertTrue(true);
        }
        catch (IllegalArgumentException notExpected) {
            Assert.fail("It shouldn't have thrown IllegalArgumentException");
        }

        // Check one GrantedAuthority-argument constructor
        try {
            GrantedAuthority ga = null;
            new GrantedAuthoritySid(ga);
            Assert.fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
            Assert.assertTrue(true);
        }

        try {
            GrantedAuthority ga = new SimpleGrantedAuthority(null);
            new GrantedAuthoritySid(ga);
            Assert.fail("It should have thrown IllegalArgumentException");
        }
        catch (IllegalArgumentException expected) {
            Assert.assertTrue(true);
        }

        try {
            GrantedAuthority ga = new SimpleGrantedAuthority("ROLE_TEST");
            new GrantedAuthoritySid(ga);
            Assert.assertTrue(true);
        }
        catch (IllegalArgumentException notExpected) {
            Assert.fail("It shouldn't have thrown IllegalArgumentException");
        }
    }

    public void testPrincipalSidEquals() throws Exception {
        Authentication authentication = new TestingAuthenticationToken("johndoe", "password");
        Sid principalSid = new PrincipalSid(authentication);

        Assert.assertFalse(principalSid.equals(null));
        Assert.assertFalse(principalSid.equals("DIFFERENT_TYPE_OBJECT"));
        Assert.assertTrue(principalSid.equals(principalSid));
        Assert.assertTrue(principalSid.equals(new PrincipalSid(authentication)));
        Assert.assertTrue(principalSid.equals(new PrincipalSid(new TestingAuthenticationToken("johndoe", null))));
        Assert.assertFalse(principalSid.equals(new PrincipalSid(new TestingAuthenticationToken("scott", null))));
        Assert.assertTrue(principalSid.equals(new PrincipalSid("johndoe")));
        Assert.assertFalse(principalSid.equals(new PrincipalSid("scott")));
    }

    public void testGrantedAuthoritySidEquals() throws Exception {
        GrantedAuthority ga = new SimpleGrantedAuthority("ROLE_TEST");
        Sid gaSid = new GrantedAuthoritySid(ga);

        Assert.assertFalse(gaSid.equals(null));
        Assert.assertFalse(gaSid.equals("DIFFERENT_TYPE_OBJECT"));
        Assert.assertTrue(gaSid.equals(gaSid));
        Assert.assertTrue(gaSid.equals(new GrantedAuthoritySid(ga)));
        Assert.assertTrue(gaSid.equals(new GrantedAuthoritySid(new SimpleGrantedAuthority("ROLE_TEST"))));
        Assert.assertFalse(gaSid.equals(new GrantedAuthoritySid(new SimpleGrantedAuthority("ROLE_NOT_EQUAL"))));
        Assert.assertTrue(gaSid.equals(new GrantedAuthoritySid("ROLE_TEST")));
        Assert.assertFalse(gaSid.equals(new GrantedAuthoritySid("ROLE_NOT_EQUAL")));
    }

    public void testPrincipalSidHashCode() throws Exception {
        Authentication authentication = new TestingAuthenticationToken("johndoe", "password");
        Sid principalSid = new PrincipalSid(authentication);

        Assert.assertTrue(principalSid.hashCode() == "johndoe".hashCode());
        Assert.assertTrue(principalSid.hashCode() == new PrincipalSid("johndoe").hashCode());
        Assert.assertTrue(principalSid.hashCode() != new PrincipalSid("scott").hashCode());
        Assert.assertTrue(principalSid.hashCode() != new PrincipalSid(new TestingAuthenticationToken("scott", "password")).hashCode());
    }

    public void testGrantedAuthoritySidHashCode() throws Exception {
        GrantedAuthority ga = new SimpleGrantedAuthority("ROLE_TEST");
        Sid gaSid = new GrantedAuthoritySid(ga);

        Assert.assertTrue(gaSid.hashCode() == "ROLE_TEST".hashCode());
        Assert.assertTrue(gaSid.hashCode() == new GrantedAuthoritySid("ROLE_TEST").hashCode());
        Assert.assertTrue(gaSid.hashCode() != new GrantedAuthoritySid("ROLE_TEST_2").hashCode());
        Assert.assertTrue(gaSid.hashCode() != new GrantedAuthoritySid(new SimpleGrantedAuthority("ROLE_TEST_2")).hashCode());
    }

    public void testGetters() throws Exception {
        Authentication authentication = new TestingAuthenticationToken("johndoe", "password");
        PrincipalSid principalSid = new PrincipalSid(authentication);
        GrantedAuthority ga = new SimpleGrantedAuthority("ROLE_TEST");
        GrantedAuthoritySid gaSid = new GrantedAuthoritySid(ga);

        Assert.assertTrue("johndoe".equals(principalSid.getPrincipal()));
        Assert.assertFalse("scott".equals(principalSid.getPrincipal()));

        Assert.assertTrue("ROLE_TEST".equals(gaSid.getGrantedAuthority()));
        Assert.assertFalse("ROLE_TEST2".equals(gaSid.getGrantedAuthority()));
    }
}
