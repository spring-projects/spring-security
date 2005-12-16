package org.acegisecurity.providers.ldap.authenticator;

import org.acegisecurity.providers.ldap.DefaultInitialDirContextFactory;
import org.acegisecurity.providers.ldap.LdapUserDetails;
import org.acegisecurity.providers.ldap.AbstractLdapServerTestCase;
import org.acegisecurity.BadCredentialsException;

/**
 * Tests {@link BindAuthenticator}.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class BindAuthenticatorTests extends AbstractLdapServerTestCase {

    private DefaultInitialDirContextFactory dirCtxFactory;
    private BindAuthenticator authenticator;

    public void setUp() throws Exception {
        dirCtxFactory = new DefaultInitialDirContextFactory();
        dirCtxFactory.setInitialContextFactory(CONTEXT_FACTORY);
        dirCtxFactory.setExtraEnvVars(EXTRA_ENV);
        dirCtxFactory.setUrl(PROVIDER_URL);
        dirCtxFactory.afterPropertiesSet();
        authenticator = new BindAuthenticator();
        authenticator.setInitialDirContextFactory(dirCtxFactory);
    }

    public void testUserDnPatternReturnsCorrectDn() throws Exception {
        authenticator.setUserDnPattern("cn={0},ou=people");
        assertEquals("cn=Joe,ou=people,"+ ROOT_DN, authenticator.getUserDn("Joe"));
    }

    public void testAuthenticationWithCorrectPasswordSucceeds() throws Exception {
        authenticator.setUserDnPattern("uid={0},ou=people");
        LdapUserDetails user = authenticator.authenticate("bob","bobspassword");
    }

    public void testAuthenticationWithWrongPasswordFails() {
        BindAuthenticator authenticator = new BindAuthenticator();

        authenticator.setInitialDirContextFactory(dirCtxFactory);
        authenticator.setUserDnPattern("uid={0},ou=people");

        try {
            authenticator.authenticate("bob","wrongpassword");
            fail("Shouldn't be able to bind with wrong password");
        } catch(BadCredentialsException expected) {
        }
    }

    public void testAuthenticationWithUserSearch() throws Exception {
        LdapUserDetails user = new LdapUserDetails("uid=bob,ou=people," + ROOT_DN, null);
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
//        authenticator.setUserDnPattern("cn={0},ou=people");
//        try {
//            authenticator.authenticate("Baz","bobspassword");
//            fail("Shouldn't be able to bind with invalid username");
//        } catch(BadCredentialsException expected) {
//        }
//    }
}

