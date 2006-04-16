package org.acegisecurity.providers.ldap.authenticator;

import org.acegisecurity.ldap.LdapUserInfo;
import org.acegisecurity.ldap.AbstractLdapServerTestCase;
import org.acegisecurity.BadCredentialsException;

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
    }

    public void testUserDnPatternReturnsCorrectDn() throws Exception {
        authenticator.setUserDnPatterns(new String[] {"cn={0},ou=people"});
        assertEquals("cn=Joe,ou=people,"+ getInitialCtxFactory().getRootDn(),
                authenticator.getUserDns("Joe").get(0));
    }

    public void testAuthenticationWithCorrectPasswordSucceeds() throws Exception {
        authenticator.setUserDnPatterns(new String[] {"uid={0},ou=people"});
        LdapUserInfo user = authenticator.authenticate("bob","bobspassword");
    }

    public void testAuthenticationWithWrongPasswordFails() {
//        BindAuthenticator authenticator = new BindAuthenticator(dirCtxFactory);

        authenticator.setUserDnPatterns(new String[] {"uid={0},ou=people"});

        try {
            authenticator.authenticate("bob","wrongpassword");
            fail("Shouldn't be able to bind with wrong password");
        } catch(BadCredentialsException expected) {
        }
    }

    public void testAuthenticationWithUserSearch() throws Exception {
        LdapUserInfo user = new LdapUserInfo("uid=bob,ou=people," + getInitialCtxFactory().getRootDn(), null);
        authenticator.setUserSearch(new MockUserSearch(user));
        authenticator.afterPropertiesSet();
        authenticator.authenticate("bob","bobspassword");
    }


// Apache DS falls apart with unknown DNs.
//
//    public void testAuthenticationWithInvalidUserNameFails() {
//        BindAuthenticator authenticator = new BindAuthenticator();
//
//        authenticator.setInitialDirContextFactory(dirCtxFactory);
//        authenticator.setUserDnPatterns("cn={0},ou=people");
//        try {
//            authenticator.authenticate("Baz","bobspassword");
//            fail("Shouldn't be able to bind with invalid username");
//        } catch(BadCredentialsException expected) {
//        }
//    }
}

