package org.acegisecurity.providers.ldap.authenticator;

import org.acegisecurity.providers.ldap.DefaultInitialDirContextFactory;
import org.acegisecurity.providers.ldap.LdapUserInfo;
import org.acegisecurity.providers.ldap.AbstractLdapServerTestCase;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.userdetails.UsernameNotFoundException;

import javax.naming.directory.BasicAttributes;

/**
 * Tests for {@link PasswordComparisonAuthenticator}.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class PasswordComparisonAuthenticatorTests extends AbstractLdapServerTestCase {
    private DefaultInitialDirContextFactory dirCtxFactory;
    private PasswordComparisonAuthenticator authenticator;

    public void setUp() throws Exception {
        dirCtxFactory = new DefaultInitialDirContextFactory(PROVIDER_URL);
        dirCtxFactory.setInitialContextFactory(CONTEXT_FACTORY);
        dirCtxFactory.setExtraEnvVars(EXTRA_ENV);
        dirCtxFactory.setManagerDn(MANAGER_USER);
        dirCtxFactory.setManagerPassword(MANAGER_PASSWORD);
        authenticator = new PasswordComparisonAuthenticator(dirCtxFactory);
        authenticator.setUserDnPatterns(new String[] {"uid={0},ou=people"});
    }

    public void tearDown() {
       // com.sun.jndi.ldap.LdapPoolManager.showStats(System.out);
    }
 /*
    public void testLdapCompareSucceedsWithCorrectPassword() {
        // Don't retrieve the password
        authenticator.setUserAttributes(new String[] {"cn"});
        // Bob has a plaintext password.
        authenticator.setPasswordEncoder(new PlaintextPasswordEncoder());
        authenticator.authenticate("bob", "bobspassword");
    }

    public void testLdapCompareSucceedsWithShaEncodedPassword() {
        authenticator = new PasswordComparisonAuthenticator();
        authenticator.setInitialDirContextFactory(dirCtxFactory);
        authenticator.setUserDnPatterns("uid={0},ou=people");
        // Don't retrieve the password
        authenticator.setUserAttributes(new String[] {"cn"});
        authenticator.authenticate("ben", "benspassword");
    }
 */
    public void testPasswordEncoderCantBeNull() {
        try {
            authenticator.setPasswordEncoder(null);
            fail("Password encoder can't be null");
        } catch(IllegalArgumentException expected) {
        }
    }

    public void testLdapPasswordCompareFailsWithWrongPassword() {
        // Don't retrieve the password
        authenticator.setUserAttributes(new String[] {"cn", "sn"});

        try {
            authenticator.authenticate("Bob", "wrongpassword");
            fail("Authentication should fail with wrong password.");
        } catch(BadCredentialsException expected) {
        }
    }

    public void testLocalPasswordComparisonSucceedsWithCorrectPassword() {
        authenticator.authenticate("Bob", "bobspassword");
    }

    public void testLocalCompareSucceedsWithShaEncodedPassword() {
        authenticator = new PasswordComparisonAuthenticator(dirCtxFactory);
        authenticator.setUserDnPatterns(new String[] {"uid={0},ou=people"});
        authenticator.authenticate("ben", "benspassword");
    }

    public void testLocalPasswordComparisonFailsWithWrongPassword() {
        try {
            authenticator.authenticate("Bob", "wrongpassword");
            fail("Authentication should fail with wrong password.");
        } catch(BadCredentialsException expected) {
        }
    }

    public void testAllAttributesAreRetrivedByDefault() {
        LdapUserInfo user = authenticator.authenticate("Bob", "bobspassword");
        System.out.println(user.getAttributes().toString());
        assertEquals("User should have 5 attributes", 5, user.getAttributes().size());

    }
/*
    public void testOnlySpecifiedAttributesAreRetrieved() throws Exception {
        authenticator.setUserAttributes(new String[] {"cn", "uid"});
        authenticator.setPasswordEncoder(new PlaintextPasswordEncoder());
        LdapUserInfo user = authenticator.authenticate("Bob", "bobspassword");
        assertEquals("Should have retrieved 2 attributes (cn, uid)",2, user.getAttributes().size());
        assertEquals("Bob Hamilton", user.getAttributes().get("cn").get());
        assertEquals("bob", user.getAttributes().get("uid").get());
    }
*/
    public void testUseOfDifferentPasswordAttribute() {
        authenticator.setPasswordAttributeName("uid");
        authenticator.authenticate("bob", "bob");
    }
/*
    public void testLdapCompareWithDifferentPasswordAttribute() {
        authenticator.setUserAttributes(new String[] {"cn"});
        authenticator.setPasswordEncoder(new PlaintextPasswordEncoder());
        authenticator.setPasswordAttributeName("uid");
        authenticator.authenticate("bob", "bob");
    }
 */

    public void testWithUserSearch() {
        authenticator = new PasswordComparisonAuthenticator(dirCtxFactory);
        assertTrue("User DN matches shouldn't be available",
                authenticator.getUserDns("Bob").isEmpty());
        LdapUserInfo user = new LdapUserInfo("uid=Bob,ou=people" + ROOT_DN,
                new BasicAttributes("userPassword","bobspassword"));
        authenticator.setUserSearch(new MockUserSearch(user));
        authenticator.authenticate("ShouldntBeUsed","bobspassword");
    }

    public void testFailedSearchGivesUserNotFoundException() throws Exception {
        authenticator = new PasswordComparisonAuthenticator(dirCtxFactory);
        assertTrue("User DN matches shouldn't be available",
                authenticator.getUserDns("Bob").isEmpty());
        authenticator.setUserSearch(new MockUserSearch(null));
        authenticator.afterPropertiesSet();

        try {
            authenticator.authenticate("Joe","password");
            fail("Expected exception on failed user search");
        } catch (UsernameNotFoundException expected) {
        }
    }
}