package org.springframework.security.ui.ntlm.ldap.authenticator;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ui.ntlm.NtlmUsernamePasswordAuthenticationToken;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;

import jcifs.smb.NtlmPasswordAuthentication;
import org.junit.Test;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class NtlmAwareLdapAuthenticatorTests {    
    /**
     * See SEC-609.
     */
    @Test(expected = BadCredentialsException.class)
    public void unauthenticatedTokenIsRejected() {
        NtlmAwareLdapAuthenticator authenticator = new NtlmAwareLdapAuthenticator(
                new DefaultSpringSecurityContextSource("ldap://blah"));

        NtlmUsernamePasswordAuthenticationToken token = new NtlmUsernamePasswordAuthenticationToken(
                new NtlmPasswordAuthentication("blah"), false);
        token.setAuthenticated(false);

        authenticator.authenticate(token);
    }

    @Test
    public void authenticatedTokenIsAccepted() {
        NtlmAwareLdapAuthenticator authenticator = new NtlmAwareLdapAuthenticator(new DefaultSpringSecurityContextSource("ldap://blah")) {
            // mimic loading of user
            protected DirContextOperations loadUser(String aUserDn, String aUserName) {
                return new DirContextAdapter();
            }
        };

        authenticator.setUserDnPatterns(new String[] {"somepattern"});

        NtlmUsernamePasswordAuthenticationToken token = new NtlmUsernamePasswordAuthenticationToken(
                new NtlmPasswordAuthentication("blah"), false);

        authenticator.authenticate(token);
    }


}
