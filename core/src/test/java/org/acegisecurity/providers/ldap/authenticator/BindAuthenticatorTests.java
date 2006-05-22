package org.acegisecurity.providers.ldap.authenticator;

import org.acegisecurity.ldap.AbstractLdapServerTestCase;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.AcegiMessageSource;
import org.acegisecurity.userdetails.ldap.LdapUserDetailsImpl;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;
import org.acegisecurity.userdetails.ldap.LdapUserDetailsMapper;

/**
 * Tests for {@link BindAuthenticator}.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class BindAuthenticatorTests extends AbstractLdapServerTestCase {

    private BindAuthenticator authenticator;

    public void onSetUp() {
        authenticator = new BindAuthenticator(getInitialCtxFactory());
        authenticator.setMessageSource(new AcegiMessageSource());        
    }

    public void testUserDnPatternReturnsCorrectDn() {
        authenticator.setUserDnPatterns(new String[] {"cn={0},ou=people"});
        assertEquals("cn=Joe,ou=people,"+ getInitialCtxFactory().getRootDn(),
                authenticator.getUserDns("Joe").get(0));
    }

    public void testAuthenticationWithCorrectPasswordSucceeds() {
        authenticator.setUserDnPatterns(new String[] {"uid={0},ou=people"});
        LdapUserDetails user = authenticator.authenticate("bob","bobspassword");
        assertEquals("bob", user.getUsername());
    }

    public void testAuthenticationWithWrongPasswordFails() {
        authenticator.setUserDnPatterns(new String[] {"uid={0},ou=people"});

        try {
            authenticator.authenticate("bob","wrongpassword");
            fail("Shouldn't be able to bind with wrong password");
        } catch(BadCredentialsException expected) {
        }
    }

    public void testAuthenticationWithUserSearch() throws Exception {
        LdapUserDetailsImpl.Essence userEssence = new LdapUserDetailsImpl.Essence();
        userEssence.setDn("uid=bob,ou=people,dc=acegisecurity,dc=org");

        authenticator.setUserSearch(new MockUserSearch(userEssence.createUserDetails()));
        authenticator.afterPropertiesSet();
        authenticator.authenticate("bob","bobspassword");
    }

    public void testAuthenticationWithInvalidUserNameFails() {
        authenticator.setUserDnPatterns(new String[] {"uid={0},ou=people"});

        try {
            authenticator.authenticate("nonexistentsuser","bobspassword");
            fail("Shouldn't be able to bind with invalid username");
        } catch(BadCredentialsException expected) {
        }
    }

    // TODO: Create separate tests for base class
    public void testRoleRetrieval() {
        authenticator.setUserDnPatterns(new String[] {"uid={0},ou=people"});
        LdapUserDetailsMapper userMapper = new LdapUserDetailsMapper();
        userMapper.setRoleAttributes(new String[] {"uid"});

        authenticator.setUserDetailsMapper(userMapper);

        LdapUserDetails user = authenticator.authenticate("bob","bobspassword");

        assertEquals(1, user.getAuthorities().length);
        assertEquals(new GrantedAuthorityImpl("ROLE_BOB"), user.getAuthorities()[0]);
    }
}

