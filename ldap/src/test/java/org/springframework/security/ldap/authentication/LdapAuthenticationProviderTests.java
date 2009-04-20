/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.ldap.authentication;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
import org.junit.Test;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.LdapAuthenticator;
import org.springframework.security.ldap.LdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;


/**
 * Tests {@link LdapAuthenticationProvider}.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapAuthenticationProviderTests {
    Mockery jmock = new JUnit4Mockery();

    //~ Methods ========================================================================================================

    @Test
    public void testSupportsUsernamePasswordAuthenticationToken() {
        LdapAuthenticationProvider ldapProvider = new LdapAuthenticationProvider(new MockAuthenticator(),
                new MockAuthoritiesPopulator());

        assertTrue(ldapProvider.supports(UsernamePasswordAuthenticationToken.class));
    }

    @Test
    public void testDefaultMapperIsSet() {
        LdapAuthenticationProvider ldapProvider = new LdapAuthenticationProvider(new MockAuthenticator(),
                new MockAuthoritiesPopulator());

        assertTrue(ldapProvider.getUserDetailsContextMapper() instanceof LdapUserDetailsMapper);
    }

    @Test
    public void testEmptyOrNullUserNameThrowsException() {
        LdapAuthenticationProvider ldapProvider = new LdapAuthenticationProvider(new MockAuthenticator(),
                new MockAuthoritiesPopulator());

        try {
            ldapProvider.authenticate(new UsernamePasswordAuthenticationToken(null, "password"));
            fail("Expected BadCredentialsException for empty username");
        } catch (BadCredentialsException expected) {}

        try {
            ldapProvider.authenticate(new UsernamePasswordAuthenticationToken("", "bobspassword"));
            fail("Expected BadCredentialsException for null username");
        } catch (BadCredentialsException expected) {}
    }

    @Test(expected=BadCredentialsException.class)
    public void usernameNotFoundExceptionIsHiddenByDefault() {
        final LdapAuthenticator authenticator = jmock.mock(LdapAuthenticator.class);
        final UsernamePasswordAuthenticationToken joe = new UsernamePasswordAuthenticationToken("joe", "password");
        jmock.checking(new Expectations() {{
            oneOf(authenticator).authenticate(joe); will(throwException(new UsernameNotFoundException("nobody")));
        }});

        LdapAuthenticationProvider provider = new LdapAuthenticationProvider(authenticator);
        provider.authenticate(joe);
    }

    @Test(expected=UsernameNotFoundException.class)
    public void usernameNotFoundExceptionIsNotHiddenIfConfigured() {
        final LdapAuthenticator authenticator = jmock.mock(LdapAuthenticator.class);
        final UsernamePasswordAuthenticationToken joe = new UsernamePasswordAuthenticationToken("joe", "password");
        jmock.checking(new Expectations() {{
            oneOf(authenticator).authenticate(joe); will(throwException(new UsernameNotFoundException("nobody")));
        }});

        LdapAuthenticationProvider provider = new LdapAuthenticationProvider(authenticator);
        provider.setHideUserNotFoundExceptions(false);
        provider.authenticate(joe);
    }

    @Test
    public void normalUsage() {
        MockAuthoritiesPopulator populator = new MockAuthoritiesPopulator();
        LdapAuthenticationProvider ldapProvider = new LdapAuthenticationProvider(new MockAuthenticator(), populator);
        LdapUserDetailsMapper userMapper = new LdapUserDetailsMapper();
        userMapper.setRoleAttributes(new String[] {"ou"});
        ldapProvider.setUserDetailsContextMapper(userMapper);

        assertNotNull(ldapProvider.getAuthoritiesPopulator());

        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken("ben", "benspassword");
        Object authDetails = new Object();
        authRequest.setDetails(authDetails);
        Authentication authResult = ldapProvider.authenticate(authRequest);
        assertEquals("benspassword", authResult.getCredentials());
        assertSame(authDetails, authResult.getDetails());
        UserDetails user = (UserDetails) authResult.getPrincipal();
        assertEquals(2, user.getAuthorities().size());
        assertEquals("{SHA}nFCebWjxfaLbHHG1Qk5UU4trbvQ=", user.getPassword());
        assertEquals("ben", user.getUsername());
        assertEquals("ben", populator.getRequestedUsername());

        ArrayList<String> authorities = new ArrayList<String>();
        authorities.add(user.getAuthorities().get(0).getAuthority());
        authorities.add(user.getAuthorities().get(1).getAuthority());

        assertTrue(authorities.contains("ROLE_FROM_ENTRY"));
        assertTrue(authorities.contains("ROLE_FROM_POPULATOR"));
    }

    @Test
    public void passwordIsSetFromUserDataIfUseAuthenticationRequestCredentialsIsFalse() {
        LdapAuthenticationProvider ldapProvider = new LdapAuthenticationProvider(new MockAuthenticator(),
                new MockAuthoritiesPopulator());
        ldapProvider.setUseAuthenticationRequestCredentials(false);

        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken("ben", "benspassword");
        Authentication authResult = ldapProvider.authenticate(authRequest);
        assertEquals("{SHA}nFCebWjxfaLbHHG1Qk5UU4trbvQ=", authResult.getCredentials());

    }

    @Test
    public void useWithNullAuthoritiesPopulatorReturnsCorrectRole() {
        LdapAuthenticationProvider ldapProvider = new LdapAuthenticationProvider(new MockAuthenticator());
        LdapUserDetailsMapper userMapper = new LdapUserDetailsMapper();
        userMapper.setRoleAttributes(new String[] {"ou"});
        ldapProvider.setUserDetailsContextMapper(userMapper);
        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken("ben", "benspassword");
        UserDetails user = (UserDetails) ldapProvider.authenticate(authRequest).getPrincipal();
        assertEquals(1, user.getAuthorities().size());
        assertEquals("ROLE_FROM_ENTRY", user.getAuthorities().get(0).getAuthority());
    }

    //~ Inner Classes ==================================================================================================

    class MockAuthenticator implements LdapAuthenticator {

        public DirContextOperations authenticate(Authentication authentication) {
            DirContextAdapter ctx = new DirContextAdapter();
            ctx.setAttributeValue("ou", "FROM_ENTRY");
            String username = authentication.getName();
            String password = (String) authentication.getCredentials();


            if (username.equals("ben") && password.equals("benspassword")) {
                ctx.setDn(new DistinguishedName("cn=ben,ou=people,dc=springframework,dc=org"));
                ctx.setAttributeValue("userPassword","{SHA}nFCebWjxfaLbHHG1Qk5UU4trbvQ=");

                return ctx;
            } else if (username.equals("jen") && password.equals("")) {
                ctx.setDn(new DistinguishedName("cn=jen,ou=people,dc=springframework,dc=org"));

                return ctx;
            }

            throw new BadCredentialsException("Authentication failed.");
        }
    }

    class MockAuthoritiesPopulator implements LdapAuthoritiesPopulator {
        String username;

        public List<GrantedAuthority> getGrantedAuthorities(DirContextOperations userCtx, String username) {
            this.username = username;
            return AuthorityUtils.createAuthorityList("ROLE_FROM_POPULATOR");
        }

        String getRequestedUsername() {
            return username;
        }
    }
}
