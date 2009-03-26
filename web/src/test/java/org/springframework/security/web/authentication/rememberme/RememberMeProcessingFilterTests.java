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

package org.springframework.security.web.authentication.rememberme;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import junit.framework.TestCase;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.MockApplicationEventPublisher;
import org.springframework.security.MockAuthenticationManager;
import org.springframework.security.MockFilterConfig;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.TestingAuthenticationToken;
import org.springframework.security.web.authentication.rememberme.NullRememberMeServices;
import org.springframework.security.web.authentication.rememberme.RememberMeProcessingFilter;
import org.springframework.security.web.authentication.rememberme.RememberMeServices;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;


/**
 * Tests {@link RememberMeProcessingFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class RememberMeProcessingFilterTests extends TestCase {
    Authentication remembered = new TestingAuthenticationToken("remembered", "password","ROLE_REMEMBERED");

    //~ Methods ========================================================================================================

    private void executeFilterInContainerSimulator(FilterConfig filterConfig, Filter filter, ServletRequest request,
        ServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {
        filter.init(filterConfig);
        filter.doFilter(request, response, filterChain);
        filter.destroy();
    }

    protected void setUp() throws Exception {
        super.setUp();
        SecurityContextHolder.clearContext();
    }

    protected void tearDown() throws Exception {
        super.tearDown();
        SecurityContextHolder.clearContext();
    }

    public void testDetectsAuthenticationManagerProperty() throws Exception {
        RememberMeProcessingFilter filter = new RememberMeProcessingFilter();
        filter.setAuthenticationManager(new MockAuthenticationManager());
        filter.setRememberMeServices(new NullRememberMeServices());

        filter.afterPropertiesSet();
        assertTrue(true);

        filter.setAuthenticationManager(null);

        try {
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testDetectsRememberMeServicesProperty() throws Exception {
        RememberMeProcessingFilter filter = new RememberMeProcessingFilter();
        filter.setAuthenticationManager(new MockAuthenticationManager());

        // check default is NullRememberMeServices
        // assertEquals(NullRememberMeServices.class, filter.getRememberMeServices().getClass());

        // check getter/setter
        filter.setRememberMeServices(new TokenBasedRememberMeServices());
        assertEquals(TokenBasedRememberMeServices.class, filter.getRememberMeServices().getClass());

        // check detects if made null
        filter.setRememberMeServices(null);

        try {
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testOperationWhenAuthenticationExistsInContextHolder() throws Exception {
        // Put an Authentication object into the SecurityContextHolder
        Authentication originalAuth = new TestingAuthenticationToken("user", "password","ROLE_A");
        SecurityContextHolder.getContext().setAuthentication(originalAuth);

        // Setup our filter correctly
        RememberMeProcessingFilter filter = new RememberMeProcessingFilter();
        filter.setAuthenticationManager(new MockAuthenticationManager());
        filter.setRememberMeServices(new MockRememberMeServices(remembered));
        filter.afterPropertiesSet();

        // Test
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("x");
        executeFilterInContainerSimulator(new MockFilterConfig(), filter, request, new MockHttpServletResponse(),
            new MockFilterChain(true));

        // Ensure filter didn't change our original object
        assertEquals(originalAuth, SecurityContextHolder.getContext().getAuthentication());
    }

    public void testOperationWhenNoAuthenticationInContextHolder() throws Exception {

        RememberMeProcessingFilter filter = new RememberMeProcessingFilter();
        filter.setAuthenticationManager(new MockAuthenticationManager());
        filter.setRememberMeServices(new MockRememberMeServices(remembered));
        filter.afterPropertiesSet();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("x");
        executeFilterInContainerSimulator(new MockFilterConfig(), filter, request, new MockHttpServletResponse(),
            new MockFilterChain(true));

        // Ensure filter setup with our remembered authentication object
        assertEquals(remembered, SecurityContextHolder.getContext().getAuthentication());
    }

    public void testOnunsuccessfulLoginIsCalledWhenProviderRejectsAuth() throws Exception {
        final Authentication failedAuth = new TestingAuthenticationToken("failed", "");

        RememberMeProcessingFilter filter = new RememberMeProcessingFilter() {
            protected void onUnsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
                super.onUnsuccessfulAuthentication(request, response, failed);
                SecurityContextHolder.getContext().setAuthentication(failedAuth);
            }
        };
        filter.setAuthenticationManager(new MockAuthenticationManager(false));
        filter.setRememberMeServices(new MockRememberMeServices(remembered));
        filter.setApplicationEventPublisher(new MockApplicationEventPublisher());
        filter.afterPropertiesSet();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("x");
        executeFilterInContainerSimulator(new MockFilterConfig(), filter, request, new MockHttpServletResponse(),
            new MockFilterChain(true));

        assertEquals(failedAuth, SecurityContextHolder.getContext().getAuthentication());
    }

    //~ Inner Classes ==================================================================================================

    private class MockFilterChain implements FilterChain {
        private boolean expectToProceed;

        public MockFilterChain(boolean expectToProceed) {
            this.expectToProceed = expectToProceed;
        }

        public void doFilter(ServletRequest request, ServletResponse response)
            throws IOException, ServletException {
            if (expectToProceed) {
                assertTrue(true);
            } else {
                fail("Did not expect filter chain to proceed");
            }
        }
    }

    private class MockRememberMeServices implements RememberMeServices {
        private Authentication authToReturn;

        public MockRememberMeServices(Authentication authToReturn) {
            this.authToReturn = authToReturn;
        }

        public Authentication autoLogin(HttpServletRequest request, HttpServletResponse response) {
            return authToReturn;
        }

        public void loginFail(HttpServletRequest request, HttpServletResponse response) {}

        public void loginSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication successfulAuthentication) {}
    }
}
