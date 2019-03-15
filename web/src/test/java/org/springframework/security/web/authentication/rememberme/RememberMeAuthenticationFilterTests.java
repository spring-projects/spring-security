/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.authentication.rememberme;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

import org.junit.*;
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
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Tests {@link RememberMeAuthenticationFilter}.
 *
 * @author Ben Alex
 */
public class RememberMeAuthenticationFilterTests {
    Authentication remembered = new TestingAuthenticationToken("remembered", "password","ROLE_REMEMBERED");

    //~ Methods ========================================================================================================

    @Before
    public void setUp() {
        SecurityContextHolder.clearContext();
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDetectsAuthenticationManagerProperty() {
        RememberMeAuthenticationFilter filter = new RememberMeAuthenticationFilter();
        filter.setAuthenticationManager(mock(AuthenticationManager.class));
        filter.setRememberMeServices(new NullRememberMeServices());

        filter.afterPropertiesSet();

        filter.setAuthenticationManager(null);

        filter.afterPropertiesSet();
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDetectsRememberMeServicesProperty() {
        RememberMeAuthenticationFilter filter = new RememberMeAuthenticationFilter();
        filter.setAuthenticationManager(mock(AuthenticationManager.class));

        // check default is NullRememberMeServices
        // assertEquals(NullRememberMeServices.class, filter.getRememberMeServices().getClass());

        // check getter/setter
        filter.setRememberMeServices(new TokenBasedRememberMeServices());
        assertEquals(TokenBasedRememberMeServices.class, filter.getRememberMeServices().getClass());

        // check detects if made null
        filter.setRememberMeServices(null);

        filter.afterPropertiesSet();
    }

    @Test
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
        FilterChain fc = mock(FilterChain.class);
        request.setRequestURI("x");
        filter.doFilter(request, new MockHttpServletResponse(), fc);

        // Ensure filter didn't change our original object
        assertSame(originalAuth, SecurityContextHolder.getContext().getAuthentication());
        verify(fc).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
    }

    @Test
    public void testOperationWhenNoAuthenticationInContextHolder() throws Exception {

        RememberMeAuthenticationFilter filter = new RememberMeAuthenticationFilter();
        AuthenticationManager am = mock(AuthenticationManager.class);
        when(am.authenticate(remembered)).thenReturn(remembered);
        filter.setAuthenticationManager(am);
        filter.setRememberMeServices(new MockRememberMeServices(remembered));
        filter.afterPropertiesSet();

        MockHttpServletRequest request = new MockHttpServletRequest();
        FilterChain fc = mock(FilterChain.class);
        request.setRequestURI("x");
        filter.doFilter(request, new MockHttpServletResponse(), fc);

        // Ensure filter setup with our remembered authentication object
        assertSame(remembered, SecurityContextHolder.getContext().getAuthentication());
        verify(fc).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
    }

    @Test
    public void onUnsuccessfulLoginIsCalledWhenProviderRejectsAuth() throws Exception {
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
        FilterChain fc = mock(FilterChain.class);
        request.setRequestURI("x");
        filter.doFilter(request, new MockHttpServletResponse(), fc);

        assertSame(failedAuth, SecurityContextHolder.getContext().getAuthentication());
        verify(fc).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
    }

    @Test
    public void authenticationSuccessHandlerIsInvokedOnSuccessfulAuthenticationIfSet() throws Exception {
        RememberMeAuthenticationFilter filter = new RememberMeAuthenticationFilter();
        AuthenticationManager am = mock(AuthenticationManager.class);
        when(am.authenticate(remembered)).thenReturn(remembered);
        filter.setAuthenticationManager(am);
        filter.setRememberMeServices(new MockRememberMeServices(remembered));
        filter.setAuthenticationSuccessHandler(new SimpleUrlAuthenticationSuccessHandler("/target"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain fc = mock(FilterChain.class);
        request.setRequestURI("x");
        filter.doFilter(request, response, fc);

        assertEquals("/target", response.getRedirectedUrl());

        // Should return after success handler is invoked, so chain should not proceed
        verifyZeroInteractions(fc);
    }

    //~ Inner Classes ==================================================================================================

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
