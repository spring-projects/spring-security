package org.acegisecurity.providers.ldap.authenticator;

import org.acegisecurity.providers.ldap.DefaultInitialDirContextFactory;
import org.acegisecurity.providers.ldap.LdapUserInfo;
import org.acegisecurity.providers.ldap.AbstractLdapServerTestCase;
import org.acegisecurity.BadCredentialsException;

/**
 * Tests for {@link BindAuthenticator}.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class BindAuthenticatorTests extends AbstractLdapServerTestCase {

    private DefaultInitialDirContextFactory dirCtxFactory;
    private BindAuthenticator authenticator;

    public void setUp() throws Exception {
        dirCtxFactory = new DefaultInitialDirContextFactory(PROVIDER_URL);
        dirCtxFactory.setInitialContextFactory(CONTEXT_FACTORY);
        dirCtxFactory.setExtraEnvVars(EXTRA_ENV);
        authenticator = new BindAuthenticator(dirCtxFactory);
    }

    public void testUserDnPatternReturnsCorrectDn() throws Exception {
        authenticator.setUserDnPatterns(new String[] {"cn={0},ou=people"});
        assertEquals("cn=Joe,ou=people,"+ ROOT_DN, authenticator.getUserDns("Joe").get(0));
    }

    public void testAuthenticationWithCorrectPasswordSucceeds() throws Exception {
        authenticator.setUserDnPatterns(new String[] {"uid={0},ou=people"});
        LdapUserInfo user = authenticator.authenticate("bob","bobspassword");
    }

    public void testAuthenticationWithWrongPasswordFails() {
        BindAuthenticator authenticator = new BindAuthenticator(dirCtxFactory);

        authenticator.setUserDnPatterns(new String[] {"uid={0},ou=people"});

        try {
            authenticator.authenticate("bob","wrongpassword");
            fail("Shouldn't be able to bind with wrong password");
        } catch(BadCredentialsException expected) {
        }
    }

    public void testAuthenticationWithUserSearch() throws Exception {
        LdapUserInfo user = new LdapUserInfo("uid=bob,ou=people," + ROOT_DN, null);
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

