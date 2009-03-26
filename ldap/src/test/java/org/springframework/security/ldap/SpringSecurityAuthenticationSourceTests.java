package org.springframework.security.ldap;

import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.AnonymousAuthenticationToken;
import org.springframework.security.providers.TestingAuthenticationToken;
import org.springframework.security.userdetails.ldap.LdapUserDetailsImpl;
import org.springframework.security.util.AuthorityUtils;
import org.springframework.ldap.core.AuthenticationSource;
import org.springframework.ldap.core.DistinguishedName;

import org.junit.After;
import static org.junit.Assert.assertEquals;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class SpringSecurityAuthenticationSourceTests {
    @Before
    @After
    public void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void principalAndCredentialsAreEmptyWithNoAuthentication() {
        AuthenticationSource source = new SpringSecurityAuthenticationSource();
        assertEquals("", source.getPrincipal());
        assertEquals("", source.getCredentials());
    }

    @Test
    public void principalIsEmptyForAnonymousUser() {
        AuthenticationSource source = new SpringSecurityAuthenticationSource();

        SecurityContextHolder.getContext().setAuthentication(
                new AnonymousAuthenticationToken("key", "anonUser", AuthorityUtils.createAuthorityList("ignored")));
        assertEquals("", source.getPrincipal());
    }

    @Test(expected=IllegalArgumentException.class)
    public void getPrincipalRejectsNonLdapUserDetailsObject() {
        AuthenticationSource source = new SpringSecurityAuthenticationSource();
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(new Object(), "password"));

        source.getPrincipal();
    }

    @Test
    public void expectedCredentialsAreReturned() {
        AuthenticationSource source = new SpringSecurityAuthenticationSource();
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(new Object(), "password"));

        assertEquals("password", source.getCredentials());
    }

    @Test
    public void expectedPrincipalIsReturned() {
        LdapUserDetailsImpl.Essence user = new LdapUserDetailsImpl.Essence();
        user.setUsername("joe");
        user.setDn(new DistinguishedName("uid=joe,ou=users"));
        AuthenticationSource source = new SpringSecurityAuthenticationSource();
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken(user.createUserDetails(), null));

        assertEquals("uid=joe,ou=users", source.getPrincipal());
    }
}
