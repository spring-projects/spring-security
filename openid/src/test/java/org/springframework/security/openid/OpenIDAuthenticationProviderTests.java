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
package org.springframework.security.openid;

import junit.framework.TestCase;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.User;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.GrantedAuthorityImpl;
import org.springframework.security.openid.AuthenticationCancelledException;
import org.springframework.security.openid.OpenIDAuthenticationProvider;
import org.springframework.security.openid.OpenIDAuthenticationStatus;
import org.springframework.security.openid.OpenIDAuthenticationToken;
import org.springframework.security.userdetails.UserDetailsService;


/**
 * Tests {@link OpenIDAuthenticationProvider}
 *
 * @author Robin Bramley, Opsera Ltd
 */
public class OpenIDAuthenticationProviderTests extends TestCase {
    //~ Static fields/initializers =====================================================================================

    private static final String USERNAME = "user.acegiopenid.com";

    //~ Methods ========================================================================================================

    /*
     * Test method for 'org.springframework.security.authentication.openid.OpenIDAuthenticationProvider.authenticate(Authentication)'
     */
    public void testAuthenticateCancel() {
        OpenIDAuthenticationProvider provider = new OpenIDAuthenticationProvider();
        provider.setUserDetailsService(new MockUserDetailsService());

        Authentication preAuth = new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.CANCELLED, USERNAME, "");

        assertFalse(preAuth.isAuthenticated());

        try {
            provider.authenticate(preAuth);
            fail("Should throw an AuthenticationException");
        } catch (AuthenticationCancelledException expected) {
            assertEquals("Log in cancelled", expected.getMessage());
        }
    }

    /*
     * Test method for 'org.springframework.security.authentication.openid.OpenIDAuthenticationProvider.authenticate(Authentication)'
     */
    public void testAuthenticateError() {
        OpenIDAuthenticationProvider provider = new OpenIDAuthenticationProvider();
        provider.setUserDetailsService(new MockUserDetailsService());

        Authentication preAuth = new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.ERROR, USERNAME, "");

        assertFalse(preAuth.isAuthenticated());

        try {
            provider.authenticate(preAuth);
            fail("Should throw an AuthenticationException");
        } catch (AuthenticationServiceException expected) {
            assertEquals("Error message from server: ", expected.getMessage());
        }
    }

    /*
     * Test method for 'org.springframework.security.authentication.openid.OpenIDAuthenticationProvider.authenticate(Authentication)'
     */
    public void testAuthenticateFailure() {
        OpenIDAuthenticationProvider provider = new OpenIDAuthenticationProvider();
        provider.setUserDetailsService(new MockUserDetailsService());

        Authentication preAuth = new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.FAILURE, USERNAME, "");

        assertFalse(preAuth.isAuthenticated());

        try {
            provider.authenticate(preAuth);
            fail("Should throw an AuthenticationException");
        } catch (BadCredentialsException expected) {
            assertEquals("Log in failed - identity could not be verified", expected.getMessage());
        }
    }

    /*
     * Test method for 'org.springframework.security.authentication.openid.OpenIDAuthenticationProvider.authenticate(Authentication)'
     */
    public void testAuthenticateSetupNeeded() {
        OpenIDAuthenticationProvider provider = new OpenIDAuthenticationProvider();
        provider.setUserDetailsService(new MockUserDetailsService());

        Authentication preAuth = new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.SETUP_NEEDED, USERNAME, "");

        assertFalse(preAuth.isAuthenticated());

        try {
            provider.authenticate(preAuth);
            fail("Should throw an AuthenticationException");
        } catch (AuthenticationServiceException expected) {
            assertEquals("The server responded setup was needed, which shouldn't happen", expected.getMessage());
        }
    }

    /*
     * Test method for 'org.springframework.security.authentication.openid.OpenIDAuthenticationProvider.authenticate(Authentication)'
     */
    public void testAuthenticateSuccess() {
        OpenIDAuthenticationProvider provider = new OpenIDAuthenticationProvider();
        provider.setUserDetailsService(new MockUserDetailsService());

        Authentication preAuth = new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.SUCCESS, USERNAME, "");

        assertFalse(preAuth.isAuthenticated());

        Authentication postAuth = provider.authenticate(preAuth);

        assertNotNull(postAuth);
        assertTrue(postAuth instanceof OpenIDAuthenticationToken);
        assertTrue(postAuth.isAuthenticated());
        assertNotNull(postAuth.getPrincipal());
        assertEquals(preAuth.getPrincipal(), postAuth.getPrincipal());
        assertNotNull(postAuth.getAuthorities());
        assertTrue(postAuth.getAuthorities().size() > 0);
        assertTrue(((OpenIDAuthenticationToken) postAuth).getStatus() == OpenIDAuthenticationStatus.SUCCESS);
        assertTrue(((OpenIDAuthenticationToken) postAuth).getMessage() == null);
    }

    public void testDetectsMissingAuthoritiesPopulator() throws Exception {
        OpenIDAuthenticationProvider provider = new OpenIDAuthenticationProvider();

        try {
            provider.afterPropertiesSet();
            fail("Should have thrown Exception");
        } catch (IllegalArgumentException expected) {
            //ignored
        }
    }

    /*
     * Test method for 'org.springframework.security.authentication.openid.OpenIDAuthenticationProvider.supports(Class)'
     */
    public void testDoesntSupport() {
        OpenIDAuthenticationProvider provider = new OpenIDAuthenticationProvider();
        provider.setUserDetailsService(new MockUserDetailsService());

        assertFalse(provider.supports(UsernamePasswordAuthenticationToken.class));
    }

    /*
     * Test method for 'org.springframework.security.authentication.openid.OpenIDAuthenticationProvider.authenticate(Authentication)'
     */
    public void testIgnoresUserPassAuthToken() {
        OpenIDAuthenticationProvider provider = new OpenIDAuthenticationProvider();
        provider.setUserDetailsService(new MockUserDetailsService());

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(USERNAME, "password");
        assertEquals(null, provider.authenticate(token));
    }

    /*
     * Test method for 'org.springframework.security.authentication.openid.OpenIDAuthenticationProvider.supports(Class)'
     */
    public void testSupports() {
        OpenIDAuthenticationProvider provider = new OpenIDAuthenticationProvider();
        provider.setUserDetailsService(new MockUserDetailsService());

        assertTrue(provider.supports(OpenIDAuthenticationToken.class));
    }

    public void testValidation() throws Exception {
        OpenIDAuthenticationProvider provider = new OpenIDAuthenticationProvider();
        provider.setUserDetailsService(new MockUserDetailsService());
        provider.afterPropertiesSet();

        provider.setUserDetailsService(null);

        try {
            provider.afterPropertiesSet();
            fail("IllegalArgumentException expected, ssoAuthoritiesPopulator is null");
        } catch (IllegalArgumentException e) {
            //expected
        }
    }

    static class MockUserDetailsService implements UserDetailsService {
        public UserDetails loadUserByUsername(String ssoUserId)
            throws AuthenticationException {
            return new User(ssoUserId, "password", true, true, true, true,
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_A"), new GrantedAuthorityImpl("ROLE_B")});
        }
    }
}
