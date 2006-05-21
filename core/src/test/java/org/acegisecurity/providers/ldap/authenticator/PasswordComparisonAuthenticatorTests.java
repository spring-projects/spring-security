package org.acegisecurity.providers.ldap.authenticator;

import org.acegisecurity.ldap.AbstractLdapServerTestCase;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.providers.encoding.PlaintextPasswordEncoder;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.acegisecurity.userdetails.ldap.LdapUserDetailsImpl;
import org.acegisecurity.userdetails.ldap.LdapUserDetailsMapper;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;

/**
 * Tests for {@link PasswordComparisonAuthenticator}.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class PasswordComparisonAuthenticatorTests extends AbstractLdapServerTestCase {
    private PasswordComparisonAuthenticator authenticator;

    public void onSetUp() {
        getInitialCtxFactory().setManagerDn(MANAGER_USER);
        getInitialCtxFactory().setManagerPassword(MANAGER_PASSWORD);
        authenticator = new PasswordComparisonAuthenticator(getInitialCtxFactory());
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
/*
    public void testLdapPasswordCompareFailsWithWrongPassword() {
        // Don't retrieve the password
        authenticator.setUserAttributes(new String[] {"cn", "sn"});

        try {
            authenticator.authenticate("Bob", "wrongpassword");
            fail("Authentication should fail with wrong password.");
        } catch(BadCredentialsException expected) {
        }
    }
*/
    public void testLocalPasswordComparisonSucceedsWithCorrectPassword() {
        authenticator.authenticate("Bob", "bobspassword");
    }

    public void testMultipleDnPatternsWorkOk() {
        authenticator.setUserDnPatterns(new String[] {"uid={0},ou=nonexistent", "uid={0},ou=people"});
        authenticator.authenticate("Bob", "bobspassword");
    }

    public void testLocalComparisonSucceedsWithShaEncodedPassword() {
        // Ben's password is SHA encoded
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
        LdapUserDetails user = authenticator.authenticate("Bob", "bobspassword");
        System.out.println(user.getAttributes().toString());
        assertEquals("User should have 5 attributes", 5, user.getAttributes().size());

    }

    public void testOnlySpecifiedAttributesAreRetrieved() throws Exception {
        authenticator.setUserAttributes(new String[] {"userPassword"});
        authenticator.setPasswordEncoder(new PlaintextPasswordEncoder());
        LdapUserDetails user = authenticator.authenticate("Bob", "bobspassword");
        assertEquals("Should have retrieved 1 attribute (userPassword)",1, user.getAttributes().size());
//        assertEquals("Bob Hamilton", user.getAttributes().get("cn").get());
//        assertEquals("bob", user.getAttributes().get("uid").get());
    }

    public void testUseOfDifferentPasswordAttribute() {
        LdapUserDetailsMapper mapper = new LdapUserDetailsMapper();
        mapper.setPasswordAttributeName("uid");
        authenticator.setPasswordAttributeName("uid");
        authenticator.setUserDetailsMapper(mapper);
        authenticator.authenticate("bob", "bob");
    }
/*
    public void testLdapCompareWithDifferentPasswordAttributeSucceeds() {
        authenticator.setUserAttributes(new String[] {"cn"});
        authenticator.setPasswordEncoder(new PlaintextPasswordEncoder());
        authenticator.setPasswordAttributeName("uid");
        authenticator.authenticate("bob", "bob");
    }
 */

    public void testWithUserSearch() {
        authenticator = new PasswordComparisonAuthenticator(getInitialCtxFactory());
        assertTrue("User DN matches shouldn't be available",
                authenticator.getUserDns("Bob").isEmpty());
        LdapUserDetailsImpl.Essence userEssence = new LdapUserDetailsImpl.Essence();
        userEssence.setDn("uid=Bob,ou=people,dc=acegisecurity,dc=org");
        userEssence.setPassword("bobspassword");

        authenticator.setUserSearch(new MockUserSearch(userEssence.createUserDetails()));
        authenticator.authenticate("ShouldntBeUsed","bobspassword");
    }

    public void testFailedSearchGivesUserNotFoundException() throws Exception {
        authenticator = new PasswordComparisonAuthenticator(getInitialCtxFactory());
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