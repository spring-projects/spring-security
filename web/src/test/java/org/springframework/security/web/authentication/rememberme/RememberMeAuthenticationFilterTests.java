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

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

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

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;


/**
 * Tests {@link RememberMeAuthenticationFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class RememberMeAuthenticationFilterTests extends TestCase {
    Authentication remembered = new TestingAuthenticationToken("remembered", "password","ROLE_REMEMBERED");

    //~ Methods ========================================================================================================

    private void executeFilterInContainerSimulator(FilterConfig filterConfig, Filter filter, ServletRequest request,
        ServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//        filter.init(filterConfig);
        filter.doFilter(request, response, filterChain);
//        filter.destroy();
    }

    protected void setUp() throws Exception {
        SecurityContextHolder.clearContext();
    }

    protected void tearDown() throws Exception {
        SecurityContextHolder.clearContext();
    }

    public void testDetectsAuthenticationManagerProperty() throws Exception {
        RememberMeAuthenticationFilter filter = new RememberMeAuthenticationFilter();
        filter.setAuthenticationManager(mock(AuthenticationManager.class));
        filter.setRememberMeServices(new NullRememberMeServices());

        filter.afterPropertiesSet();

        filter.setAuthenticationManager(null);

        try {
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testDetectsRememberMeServicesProperty() throws Exception {
        RememberMeAuthenticationFilter filter = new RememberMeAuthenticationFilter();
        filter.setAuthenticationManager(mock(AuthenticationManager.class));

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
        RememberMeAuthenticationFilter filter = new RememberMeAuthenticationFilter();
        filter.setAuthenticationManager(mock(AuthenticationManager.class));
        filter.setRememberMeServices(new MockRememberMeServices(remembered));
        filter.afterPropertiesSet();

        // Test
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("x");
        executeFilterInContainerSimulator(mock(FilterConfig.class), filter, request, new MockHttpServletResponse(),
            new MockFilterChain(true));

        // Ensure filter didn't change our original object
        assertEquals(originalAuth, SecurityContextHolder.getContext().getAuthentication());
    }

    public void testOperationWhenNoAuthenticationInContextHolder() throws Exception {

        RememberMeAuthenticationFilter filter = new RememberMeAuthenticationFilter();
        AuthenticationManager am = mock(AuthenticationManager.class);
        when(am.authenticate(remembered)).thenReturn(remembered);
        filter.setAuthenticationManager(am);
        filter.setRememberMeServices(new MockRememberMeServices(remembered));
        filter.afterPropertiesSet();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("x");
        executeFilterInContainerSimulator(mock(FilterConfig.class), filter, request, new MockHttpServletResponse(),
            new MockFilterChain(true));

        // Ensure filter setup with our remembered authentication object
        assertEquals(remembered, SecurityContextHolder.getContext().getAuthentication());
    }

    public void testOnUnsuccessfulLoginIsCalledWhenProviderRejectsAuth() throws Exception {
        final Authentication failedAuth = new TestingAuthenticationToken("failed", "");

        RememberMeAuthenticationFilter filter = new RememberMeAuthenticationFilter() {
            protected void onUnsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
                super.onUnsuccessfulAuthentication(request, response, failed);
                SecurityContextHolder.getContext().setAuthentication(failedAuth);
            }
        };
        AuthenticationManager am = mock(AuthenticationManager.class);
        when(am.authenticate(any(Authentication.class))).thenThrow(new BadCredentialsException(""));
        filter.setAuthenticationManager(am);
        filter.setRememberMeServices(new MockRememberMeServices(remembered));
        filter.setApplicationEventPublisher(mock(ApplicationEventPublisher.class));
        filter.afterPropertiesSet();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("x");
        executeFilterInContainerSimulator(mock(FilterConfig.class), filter, request, new MockHttpServletResponse(),
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
