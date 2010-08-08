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

package org.springframework.security.web.authentication;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockFilterConfig;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;


/**
 * Tests {@link AbstractAuthenticationProcessingFilter}.
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
@SuppressWarnings("deprecation")
public class AbstractAuthenticationProcessingFilterTests {
    SavedRequestAwareAuthenticationSuccessHandler successHandler;
    SimpleUrlAuthenticationFailureHandler failureHandler;
    //~ Methods ========================================================================================================

    private MockHttpServletRequest createMockAuthenticationRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        request.setServletPath("/j_mock_post");
        request.setScheme("http");
        request.setServerName("www.example.com");
        request.setRequestURI("/mycontext/j_mock_post");
        request.setContextPath("/mycontext");

        return request;
    }


    @Before
    public void setUp() throws Exception {
        successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successHandler.setDefaultTargetUrl("/logged_in.jsp");
        failureHandler = new SimpleUrlAuthenticationFailureHandler();
        failureHandler.setDefaultFailureUrl("/failed.jsp");
        SecurityContextHolder.clearContext();
    }

    @After
    public void tearDown() throws Exception {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testDefaultProcessesFilterUrlMatchesWithPathParameter() {
        MockHttpServletRequest request = createMockAuthenticationRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockAuthenticationFilter filter = new MockAuthenticationFilter();
        filter.setFilterProcessesUrl("/j_spring_security_check");

        request.setRequestURI("/mycontext/j_spring_security_check;jsessionid=I8MIONOSTHOR");
        assertTrue(filter.requiresAuthentication(request, response));
    }

    @Test
    public void testFilterProcessesUrlVariationsRespected() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = createMockAuthenticationRequest();
        request.setServletPath("/j_OTHER_LOCATION");
        request.setRequestURI("/mycontext/j_OTHER_LOCATION");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig(null, null);

        // Setup our expectation that the filter chain will not be invoked, as we redirect to defaultTargetUrl
        MockFilterChain chain = new MockFilterChain(false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Setup our test object, to grant access
        MockAuthenticationFilter filter = new MockAuthenticationFilter(true);
        filter.setFilterProcessesUrl("/j_OTHER_LOCATION");
        filter.setAuthenticationSuccessHandler(successHandler);

        // Test
        filter.doFilter(request, response, chain);
        assertEquals("/mycontext/logged_in.jsp", response.getRedirectedUrl());
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals("test", SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
    }

    @Test
    public void testGettersSetters() throws Exception {
        AbstractAuthenticationProcessingFilter filter = new MockAuthenticationFilter();
        filter.setAuthenticationManager(mock(AuthenticationManager.class));
        filter.setFilterProcessesUrl("/p");
        filter.afterPropertiesSet();

        assertNotNull(filter.getRememberMeServices());
        filter.setRememberMeServices(new TokenBasedRememberMeServices());
        assertEquals(TokenBasedRememberMeServices.class, filter.getRememberMeServices().getClass());
        assertTrue(filter.getAuthenticationManager() != null);
        assertEquals("/p", filter.getFilterProcessesUrl());
    }

    @Test
    public void testIgnoresAnyServletPathOtherThanFilterProcessesUrl() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = createMockAuthenticationRequest();
        request.setServletPath("/some.file.html");
        request.setRequestURI("/mycontext/some.file.html");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig(null, null);

        // Setup our expectation that the filter chain will be invoked, as our request is for a page the filter isn't monitoring
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Setup our test object, to deny access
        MockAuthenticationFilter filter = new MockAuthenticationFilter(false);

        // Test
        filter.doFilter(request, response, chain);
    }

    @Test
    public void testNormalOperationWithDefaultFilterProcessesUrl() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = createMockAuthenticationRequest();
        HttpSession sessionPreAuth = request.getSession();

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig(null, null);

        // Setup our expectation that the filter chain will not be invoked, as we redirect to defaultTargetUrl
        MockFilterChain chain = new MockFilterChain(false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Setup our test object, to grant access
        MockAuthenticationFilter filter = new MockAuthenticationFilter(true);

        filter.setFilterProcessesUrl("/j_mock_post");
        filter.setSessionAuthenticationStrategy(mock(SessionAuthenticationStrategy.class));
        filter.setAuthenticationSuccessHandler(successHandler);
        filter.setAuthenticationFailureHandler(failureHandler);
        filter.setAuthenticationManager(mock(AuthenticationManager.class));
        filter.afterPropertiesSet();

        // Test
        filter.doFilter(request, response, chain);
        assertEquals("/mycontext/logged_in.jsp", response.getRedirectedUrl());
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals("test", SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
        // Should still have the same session
        assertEquals(sessionPreAuth, request.getSession());
    }

    @Test
    public void testStartupDetectsInvalidAuthenticationManager() throws Exception {
        AbstractAuthenticationProcessingFilter filter = new MockAuthenticationFilter();
        filter.setAuthenticationFailureHandler(failureHandler);
        successHandler.setDefaultTargetUrl("/");
        filter.setAuthenticationSuccessHandler(successHandler);
        filter.setFilterProcessesUrl("/j_spring_security_check");

        try {
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("authenticationManager must be specified", expected.getMessage());
        }
    }

    @Test
    public void testStartupDetectsInvalidFilterProcessesUrl() throws Exception {
        AbstractAuthenticationProcessingFilter filter = new MockAuthenticationFilter();
        filter.setAuthenticationFailureHandler(failureHandler);
        filter.setAuthenticationManager(mock(AuthenticationManager.class));
        filter.setAuthenticationSuccessHandler(successHandler);
        filter.setFilterProcessesUrl(null);

        try {
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("filterProcessesUrl must be specified", expected.getMessage());
        }
    }

    @Test
    public void testSuccessLoginThenFailureLoginResultsInSessionLosingToken() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = createMockAuthenticationRequest();

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig(null, null);

        // Setup our expectation that the filter chain will not be invoked, as we redirect to defaultTargetUrl
        MockFilterChain chain = new MockFilterChain(false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Setup our test object, to grant access
        MockAuthenticationFilter filter = new MockAuthenticationFilter(true);
        filter.setFilterProcessesUrl("/j_mock_post");
        filter.setAuthenticationSuccessHandler(successHandler);

        // Test
        filter.doFilter(request, response, chain);
        assertEquals("/mycontext/logged_in.jsp", response.getRedirectedUrl());
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals("test", SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());

        // Now try again but this time have filter deny access
        // Setup our HTTP request
        // Setup our expectation that the filter chain will not be invoked, as we redirect to authenticationFailureUrl
        chain = new MockFilterChain(false);
        response = new MockHttpServletResponse();

        // Setup our test object, to deny access
        filter = new MockAuthenticationFilter(false);
        filter.setFilterProcessesUrl("/j_mock_post");
        filter.setAuthenticationFailureHandler(failureHandler);

        // Test
        filter.doFilter(request, response, chain);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void testSuccessfulAuthenticationInvokesSuccessHandlerAndSetsContext() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = createMockAuthenticationRequest();

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig(null, null);

        // Setup our expectation that the filter chain will be invoked, as we want to go to the location requested in the session
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Setup our test object, to grant access
        MockAuthenticationFilter filter = new MockAuthenticationFilter(true);
        filter.setFilterProcessesUrl("/j_mock_post");
        AuthenticationSuccessHandler successHandler = mock(AuthenticationSuccessHandler.class);
        filter.setAuthenticationSuccessHandler(successHandler);

        // Test
        filter.doFilter(request, response, chain);

        verify(successHandler).onAuthenticationSuccess(any(HttpServletRequest.class), any(HttpServletResponse.class),
                any(Authentication.class));

        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void testFailedAuthenticationInvokesFailureHandler() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = createMockAuthenticationRequest();

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig(null, null);

        // Setup our expectation that the filter chain will not be invoked, as we redirect to authenticationFailureUrl
        MockFilterChain chain = new MockFilterChain(false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Setup our test object, to deny access
        MockAuthenticationFilter filter = new MockAuthenticationFilter(false);
        AuthenticationFailureHandler failureHandler = mock(AuthenticationFailureHandler.class);
        filter.setAuthenticationFailureHandler(failureHandler);

        // Test
        filter.doFilter(request, response, chain);

        verify(failureHandler).onAuthenticationFailure(any(HttpServletRequest.class), any(HttpServletResponse.class),
                any(AuthenticationException.class));

        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    /**
     * SEC-571
     */
    @Test
    public void testNoSessionIsCreatedIfAllowSessionCreationIsFalse() throws Exception {
        MockHttpServletRequest request = createMockAuthenticationRequest();

        MockFilterConfig config = new MockFilterConfig(null, null);
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Reject authentication, so exception would normally be stored in session
        MockAuthenticationFilter filter = new MockAuthenticationFilter(false);
        failureHandler.setAllowSessionCreation(false);
        filter.setAuthenticationFailureHandler(failureHandler);

        filter.doFilter(request, response, chain);

        assertNull(request.getSession(false));
    }

    /**
     * SEC-462
     */
    @Test
    public void testLoginErrorWithNoFailureUrlSendsUnauthorizedStatus() throws Exception {
        MockHttpServletRequest request = createMockAuthenticationRequest();

        MockFilterConfig config = new MockFilterConfig(null, null);
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        MockAuthenticationFilter filter = new MockAuthenticationFilter(false);
        successHandler.setDefaultTargetUrl("http://monkeymachine.co.uk/");
        filter.setAuthenticationSuccessHandler(successHandler);

        filter.doFilter(request, response, chain);

        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
    }


    //~ Inner Classes ==================================================================================================

    private class MockAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
        private AuthenticationException exceptionToThrow;
        private boolean grantAccess;

        public MockAuthenticationFilter(boolean grantAccess) {
            this();
            setRememberMeServices(new NullRememberMeServices());
            this.grantAccess = grantAccess;
            this.exceptionToThrow = new BadCredentialsException("Mock requested to do so");
        }

        private MockAuthenticationFilter() {
            super("/j_mock_post");
        }

        public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
            if (grantAccess) {
                return new UsernamePasswordAuthenticationToken("test", "test", AuthorityUtils.createAuthorityList("TEST"));
            } else {
                throw exceptionToThrow;
            }
        }

        public boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
            return super.requiresAuthentication(request, response);
        }
    }

    private class MockFilterChain implements FilterChain {
        private boolean expectToProceed;

        public MockFilterChain(boolean expectToProceed) {
            this.expectToProceed = expectToProceed;
        }

        public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
            if (expectToProceed) {
                assertTrue(true);
            } else {
                fail("Did not expect filter chain to proceed");
            }
        }
    }
}
