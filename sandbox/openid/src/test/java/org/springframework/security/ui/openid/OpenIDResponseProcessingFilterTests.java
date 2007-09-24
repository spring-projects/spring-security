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
package org.springframework.security.ui.openid;

import junit.framework.TestCase;

import org.springframework.security.AbstractAuthenticationManager;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.BadCredentialsException;

import org.springframework.security.providers.cas.CasAuthoritiesPopulator;
import org.springframework.security.providers.openid.MockAuthoritiesPopulator;
import org.springframework.security.providers.openid.OpenIDAuthenticationStatus;
import org.springframework.security.providers.openid.OpenIDAuthenticationToken;

import org.springframework.security.ui.openid.consumers.MockOpenIDConsumer;

import org.springframework.mock.web.MockHttpServletRequest;


/**
 * Tests {@link OpenIDResponseProcessingFilter}
 *
 * @author Robin Bramley, Opsera Ltd
 */
public class OpenIDResponseProcessingFilterTests extends TestCase {
    //~ Static fields/initializers =====================================================================================

    private static final String USERNAME = "user.acegiopenid.com";

    //~ Methods ========================================================================================================

    /*
     * Test method for 'org.springframework.security.ui.openid.OpenIDResponseProcessingFilter.attemptAuthentication(HttpServletRequest)'
     */
    public void testAttemptAuthenticationFailure() {
        // set up mock objects
        MockOpenIDAuthenticationManager mockAuthManager = new MockOpenIDAuthenticationManager(false);

        OpenIDAuthenticationToken token = new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.FAILURE, USERNAME, "");
        MockOpenIDConsumer mockConsumer = new MockOpenIDConsumer();
        mockConsumer.setToken(token);

        MockHttpServletRequest req = new MockHttpServletRequest();

        OpenIDResponseProcessingFilter filter = new OpenIDResponseProcessingFilter();
        filter.setConsumer(mockConsumer);
        filter.setAuthenticationManager(mockAuthManager);

        // run test
        try {
            filter.attemptAuthentication(req);
            fail("Should've thrown exception");
        } catch (BadCredentialsException expected) {
            assertEquals("MockOpenIDAuthenticationManager instructed to deny access", expected.getMessage());
        }
    }

    /*
     * Test method for 'org.springframework.security.ui.openid.OpenIDResponseProcessingFilter.attemptAuthentication(HttpServletRequest)'
     */
    public void testAttemptAuthenticationHttpServletRequest() {
        // set up mock objects
        MockOpenIDAuthenticationManager mockAuthManager = new MockOpenIDAuthenticationManager(true);

        OpenIDAuthenticationToken token = new OpenIDAuthenticationToken(OpenIDAuthenticationStatus.SUCCESS, USERNAME, "");
        MockOpenIDConsumer mockConsumer = new MockOpenIDConsumer();
        mockConsumer.setToken(token);

        MockHttpServletRequest req = new MockHttpServletRequest();

        OpenIDResponseProcessingFilter filter = new OpenIDResponseProcessingFilter();
        filter.setConsumer(mockConsumer);
        filter.setAuthenticationManager(mockAuthManager);

        // run test
        Authentication authentication = filter.attemptAuthentication(req);

        // assertions
        assertNotNull(authentication);
        assertTrue(authentication.isAuthenticated());
        assertTrue(authentication instanceof OpenIDAuthenticationToken);
        assertNotNull(authentication.getPrincipal());
        assertEquals(USERNAME, authentication.getPrincipal());
        assertNotNull(authentication.getAuthorities());
        assertTrue(authentication.getAuthorities().length > 0);
        assertTrue(((OpenIDAuthenticationToken) authentication).getStatus() == OpenIDAuthenticationStatus.SUCCESS);
        assertTrue(((OpenIDAuthenticationToken) authentication).getMessage() == null);
    }

    /*
     * Test method for 'org.springframework.security.ui.openid.OpenIDResponseProcessingFilter.getDefaultFilterProcessesUrl()'
     */
    public void testGetDefaultFilterProcessesUrl() {
        OpenIDResponseProcessingFilter filter = new OpenIDResponseProcessingFilter();
        assertEquals("/j_spring_openid_security_check", filter.getDefaultFilterProcessesUrl());
    }

    //~ Inner Classes ==================================================================================================

    // private mock AuthenticationManager
    private class MockOpenIDAuthenticationManager extends AbstractAuthenticationManager {
        private CasAuthoritiesPopulator ssoAuthoritiesPopulator;
        private boolean grantAccess = true;

        public MockOpenIDAuthenticationManager(boolean grantAccess) {
            this.grantAccess = grantAccess;
            ssoAuthoritiesPopulator = new MockAuthoritiesPopulator();
        }

        public MockOpenIDAuthenticationManager() {
            super();
            ssoAuthoritiesPopulator = new MockAuthoritiesPopulator();
        }

        public Authentication doAuthentication(Authentication authentication)
            throws AuthenticationException {
            if (grantAccess) {
                return new OpenIDAuthenticationToken(ssoAuthoritiesPopulator.getUserDetails(USERNAME).getAuthorities(),
                    OpenIDAuthenticationStatus.SUCCESS, USERNAME);
            } else {
                throw new BadCredentialsException("MockOpenIDAuthenticationManager instructed to deny access");
            }
        }
    }
}
