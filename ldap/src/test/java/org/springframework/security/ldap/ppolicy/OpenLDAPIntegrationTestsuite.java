package org.springframework.security.ldap.ppolicy;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.userdetails.LdapUserDetailsImpl;

/**
 * Test cases which run against an OpenLDAP server.
 * <p>
 * Run the script in the module root to start the server and import the data before running.
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public class OpenLDAPIntegrationTestSuite {
    PasswordPolicyAwareContextSource cs;

    @Before
    public void createContextSource() throws Exception {
        cs = new PasswordPolicyAwareContextSource("ldap://localhost:22389/dc=springsource,dc=com");
        cs.setUserDn("cn=admin,dc=springsource,dc=com");
        cs.setPassword("password");
        cs.afterPropertiesSet();
    }

    @Test
    public void simpleBindSucceeds() throws Exception {
        BindAuthenticator authenticator = new BindAuthenticator(cs);
        authenticator.setUserDnPatterns(new String[] {"uid={0},ou=users"});
        LdapAuthenticationProvider provider = new LdapAuthenticationProvider(authenticator);
        provider.authenticate(new UsernamePasswordAuthenticationToken("luke","password"));
    }

    @Test(expected=LockedException.class)
    public void repeatedBindWithWrongPasswordLocksAccount() throws Exception {
        BindAuthenticator authenticator = new BindAuthenticator(cs);
        authenticator.setUserDnPatterns(new String[] {"uid={0},ou=users"});
        LdapAuthenticationProvider provider = new LdapAuthenticationProvider(authenticator);
        for (int count=1; count < 4; count++) {
            try {
                Authentication a = provider.authenticate(new UsernamePasswordAuthenticationToken("lockme","wrong"));
                LdapUserDetailsImpl ud = (LdapUserDetailsImpl) a.getPrincipal();
                assertTrue(ud.getTimeBeforeExpiration() < Integer.MAX_VALUE && ud.getTimeBeforeExpiration() > 0);
            } catch (BadCredentialsException expected) {
            }
        }
    }

    @Test
    public void passwordExpiryTimeIsDetectedCorrectly() throws Exception {
        BindAuthenticator authenticator = new BindAuthenticator(cs);
        authenticator.setUserDnPatterns(new String[] {"uid={0},ou=users"});
        LdapAuthenticationProvider provider = new LdapAuthenticationProvider(authenticator);
        Authentication a = provider.authenticate(new UsernamePasswordAuthenticationToken("expireme","password"));
        PasswordPolicyData ud = (LdapUserDetailsImpl) a.getPrincipal();
        assertTrue(ud.getTimeBeforeExpiration() < Integer.MAX_VALUE && ud.getTimeBeforeExpiration() > 0);
    }

}
