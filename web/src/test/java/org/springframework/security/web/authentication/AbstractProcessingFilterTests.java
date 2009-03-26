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

import java.io.IOException;
import java.util.Properties;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import junit.framework.TestCase;

import org.springframework.mock.web.MockFilterConfig;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.AccountExpiredException;
import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.BadCredentialsException;
import org.springframework.security.MockAuthenticationManager;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.util.AuthorityUtils;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.authentication.AbstractProcessingFilter;
import org.springframework.security.web.authentication.ExceptionMappingAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.rememberme.NullRememberMeServices;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.security.web.savedrequest.SavedRequest;


/**
 * Tests {@link AbstractProcessingFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AbstractProcessingFilterTests extends TestCase {
    SavedRequestAwareAuthenticationSuccessHandler successHandler;
    SimpleUrlAuthenticationFailureHandler failureHandler;
    //~ Methods ========================================================================================================

    private MockHttpServletRequest createMockRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        request.setServletPath("/j_mock_post");
        request.setScheme("http");
        request.setServerName("www.example.com");
        request.setRequestURI("/mycontext/j_mock_post");
        request.setContextPath("/mycontext");

        return request;
    }

    private void executeFilterInContainerSimulator(FilterConfig filterConfig, Filter filter, ServletRequest request,
        ServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        filter.init(filterConfig);
        filter.doFilter(request, response, filterChain);
        filter.destroy();
    }

    private SavedRequest makeSavedRequestForUrl() {
        MockHttpServletRequest request = createMockRequest();
        request.setMethod("GET");
        request.setServletPath("/some_protected_file.html");
        request.setScheme("http");
        request.setServerName("www.example.com");
        request.setRequestURI("/mycontext/some_protected_file.html");

        return new SavedRequest(request, new PortResolverImpl());
    }

//    private SavedRequest makePostSavedRequestForUrl() {
//        MockHttpServletRequest request = createMockRequest();
//        request.setServletPath("/some_protected_file.html");
//        request.setScheme("http");
//        request.setServerName("www.example.com");
//        request.setRequestURI("/mycontext/post/some_protected_file.html");
//        request.setMethod("POST");
//
//        return new SavedRequest(request, new PortResolverImpl());
//    }

    protected void setUp() throws Exception {
        super.setUp();
        successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successHandler.setDefaultTargetUrl("/logged_in.jsp");
        failureHandler = new SimpleUrlAuthenticationFailureHandler();
        failureHandler.setDefaultFailureUrl("/failed.jsp");
        SecurityContextHolder.clearContext();
    }

    protected void tearDown() throws Exception {
        super.tearDown();
        SecurityContextHolder.clearContext();
    }

    public void testDefaultProcessesFilterUrlMatchesWithPathParameter() {
        MockHttpServletRequest request = createMockRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockAbstractProcessingFilter filter = new MockAbstractProcessingFilter();
        filter.setFilterProcessesUrl("/j_spring_security_check");

        request.setRequestURI("/mycontext/j_spring_security_check;jsessionid=I8MIONOSTHOR");
        assertTrue(filter.requiresAuthentication(request, response));
    }

    public void testFailedAuthenticationRedirectsAppropriately() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = createMockRequest();

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig(null, null);

        // Setup our expectation that the filter chain will not be invoked, as we redirect to authenticationFailureUrl
        MockFilterChain chain = new MockFilterChain(false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Setup our test object, to deny access
        MockAbstractProcessingFilter filter = new MockAbstractProcessingFilter(false);
        filter.setAuthenticationFailureHandler(failureHandler);

        // Test
        executeFilterInContainerSimulator(config, filter, request, response, chain);

        assertEquals("/mycontext/failed.jsp", response.getRedirectedUrl());
        assertNull(SecurityContextHolder.getContext().getAuthentication());

        //Prepare again, this time using the exception mapping
        filter = new MockAbstractProcessingFilter(new AccountExpiredException("You're account is expired"));
        ExceptionMappingAuthenticationFailureHandler failureHandler = new ExceptionMappingAuthenticationFailureHandler();
        filter.setAuthenticationFailureHandler(failureHandler);
        Properties exceptionMappings = new Properties();
        exceptionMappings.setProperty(AccountExpiredException.class.getName(), "/accountExpired.jsp");
        failureHandler.setExceptionMappings(exceptionMappings);
        response = new MockHttpServletResponse();

        // Test
        executeFilterInContainerSimulator(config, filter, request, response, chain);

        assertEquals("/mycontext/accountExpired.jsp", response.getRedirectedUrl());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    public void testFilterProcessesUrlVariationsRespected() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = createMockRequest();
        request.setServletPath("/j_OTHER_LOCATION");
        request.setRequestURI("/mycontext/j_OTHER_LOCATION");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig(null, null);

        // Setup our expectation that the filter chain will not be invoked, as we redirect to defaultTargetUrl
        MockFilterChain chain = new MockFilterChain(false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Setup our test object, to grant access
        MockAbstractProcessingFilter filter = new MockAbstractProcessingFilter(true);
        filter.setFilterProcessesUrl("/j_OTHER_LOCATION");
        filter.setAuthenticationSuccessHandler(successHandler);

        // Test
        executeFilterInContainerSimulator(config, filter, request, response, chain);
        assertEquals("/mycontext/logged_in.jsp", response.getRedirectedUrl());
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals("test", SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
    }

    public void testGettersSetters() throws Exception {
        AbstractProcessingFilter filter = new MockAbstractProcessingFilter();
        filter.setAuthenticationManager(new MockAuthenticationManager());
        filter.setFilterProcessesUrl("/p");
        filter.afterPropertiesSet();

        assertNotNull(filter.getRememberMeServices());
        filter.setRememberMeServices(new TokenBasedRememberMeServices());
        assertEquals(TokenBasedRememberMeServices.class, filter.getRememberMeServices().getClass());
        assertTrue(filter.getAuthenticationManager() != null);
        assertEquals("/p", filter.getFilterProcessesUrl());
    }

    public void testIgnoresAnyServletPathOtherThanFilterProcessesUrl() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = createMockRequest();
        request.setServletPath("/some.file.html");
        request.setRequestURI("/mycontext/some.file.html");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig(null, null);

        // Setup our expectation that the filter chain will be invoked, as our request is for a page the filter isn't monitoring
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Setup our test object, to deny access
        MockAbstractProcessingFilter filter = new MockAbstractProcessingFilter(false);

        // Test
        executeFilterInContainerSimulator(config, filter, request, response, chain);
    }

    public void testNormalOperationWithDefaultFilterProcessesUrl() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = createMockRequest();
        HttpSession sessionPreAuth = request.getSession();

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig(null, null);

        // Setup our expectation that the filter chain will not be invoked, as we redirect to defaultTargetUrl
        MockFilterChain chain = new MockFilterChain(false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Setup our test object, to grant access
        MockAbstractProcessingFilter filter = new MockAbstractProcessingFilter(true);

        filter.setFilterProcessesUrl("/j_mock_post");
        filter.setAuthenticationSuccessHandler(successHandler);
        filter.setAuthenticationFailureHandler(failureHandler);
        filter.setAuthenticationManager(new MockAuthenticationManager(true));
        filter.afterPropertiesSet();

        // Test
        executeFilterInContainerSimulator(config, filter, request, response, chain);
        assertEquals("/mycontext/logged_in.jsp", response.getRedirectedUrl());
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals("test", SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
        // Should still have the same session
        assertEquals(sessionPreAuth, request.getSession());
    }

    public void testStartupDetectsInvalidAuthenticationManager() throws Exception {
        AbstractProcessingFilter filter = new MockAbstractProcessingFilter();
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

    public void testStartupDetectsInvalidFilterProcessesUrl() throws Exception {
        AbstractProcessingFilter filter = new MockAbstractProcessingFilter();
        filter.setAuthenticationFailureHandler(failureHandler);
        filter.setAuthenticationManager(new MockAuthenticationManager());
        filter.setAuthenticationSuccessHandler(successHandler);
        filter.setFilterProcessesUrl(null);

        try {
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("filterProcessesUrl must be specified", expected.getMessage());
        }
    }

    public void testSuccessLoginThenFailureLoginResultsInSessionLosingToken() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = createMockRequest();

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig(null, null);

        // Setup our expectation that the filter chain will not be invoked, as we redirect to defaultTargetUrl
        MockFilterChain chain = new MockFilterChain(false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Setup our test object, to grant access
        MockAbstractProcessingFilter filter = new MockAbstractProcessingFilter(true);
        filter.setFilterProcessesUrl("/j_mock_post");
        filter.setAuthenticationSuccessHandler(successHandler);

        // Test
        executeFilterInContainerSimulator(config, filter, request, response, chain);
        assertEquals("/mycontext/logged_in.jsp", response.getRedirectedUrl());
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals("test", SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());

        // Now try again but this time have filter deny access
        // Setup our HTTP request
        // Setup our expectation that the filter chain will not be invoked, as we redirect to authenticationFailureUrl
        chain = new MockFilterChain(false);
        response = new MockHttpServletResponse();

        // Setup our test object, to deny access
        filter = new MockAbstractProcessingFilter(false);
        filter.setFilterProcessesUrl("/j_mock_post");
        filter.setAuthenticationFailureHandler(failureHandler);

        // Test
        executeFilterInContainerSimulator(config, filter, request, response, chain);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    public void testSuccessfulAuthenticationButWithAlwaysUseDefaultTargetUrlCausesRedirectToDefaultTargetUrl()
            throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = createMockRequest();
        request.getSession().setAttribute(SavedRequest.SPRING_SECURITY_SAVED_REQUEST_KEY, makeSavedRequestForUrl());

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig(null, null);

        // Setup our expectation that the filter chain will be invoked, as we want to go to the location requested in the session
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Setup our test object, to grant access
        MockAbstractProcessingFilter filter = new MockAbstractProcessingFilter(true);
        filter.setFilterProcessesUrl("/j_mock_post");
        successHandler.setDefaultTargetUrl("/foobar");
        successHandler.setAlwaysUseDefaultTargetUrl(true);
        filter.setAuthenticationSuccessHandler(successHandler);

        // Test
        executeFilterInContainerSimulator(config, filter, request, response, chain);
        assertEquals("/mycontext/foobar", response.getRedirectedUrl());
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
    }

    public void testSuccessfulAuthenticationCausesRedirectToSessionSpecifiedUrl() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = createMockRequest();
        request.getSession().setAttribute(SavedRequest.SPRING_SECURITY_SAVED_REQUEST_KEY, makeSavedRequestForUrl());

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig(null, null);

        // Setup our expectation that the filter chain will be invoked, as we want to go to the location requested in the session
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Setup our test object, to grant access
        MockAbstractProcessingFilter filter = new MockAbstractProcessingFilter(true);
        filter.setFilterProcessesUrl("/j_mock_post");

        // Test
        executeFilterInContainerSimulator(config, filter, request, response, chain);
        assertEquals(makeSavedRequestForUrl().getFullRequestUrl(), response.getRedirectedUrl());
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
    }

    /**
     * SEC-297 fix.
     */
    public void testFullDefaultTargetUrlDoesNotHaveContextPathPrepended() throws Exception {
        MockHttpServletRequest request = createMockRequest();
        MockFilterConfig config = new MockFilterConfig(null, null);

        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Setup our test object, to grant access
        MockAbstractProcessingFilter filter = new MockAbstractProcessingFilter(true);
        successHandler.setDefaultTargetUrl("https://monkeymachine.co.uk/");
        successHandler.setAlwaysUseDefaultTargetUrl(true);
        filter.setAuthenticationSuccessHandler(successHandler);

        executeFilterInContainerSimulator(config, filter, request, response, chain);
        assertEquals("https://monkeymachine.co.uk/", response.getRedirectedUrl());
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
    }

    public void testNewSessionIsCreatedIfInvalidateSessionOnSuccessfulAuthenticationIsSet() throws Exception {
        MockHttpServletRequest request = createMockRequest();
        HttpSession oldSession = request.getSession();
        oldSession.setAttribute("test","test");
        MockFilterConfig config = new MockFilterConfig(null, null);

        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Setup our test object, to grant access
        MockAbstractProcessingFilter filter = new MockAbstractProcessingFilter(true);
        filter.setInvalidateSessionOnSuccessfulAuthentication(true);
        successHandler.setDefaultTargetUrl("http://monkeymachine.co.uk/");
        filter.setAuthenticationSuccessHandler(successHandler);

        executeFilterInContainerSimulator(config, filter, request, response, chain);

        HttpSession newSession = request.getSession();
        assertFalse(newSession.getId().equals(oldSession.getId()));
        assertEquals("test", newSession.getAttribute("test"));
    }

    public void testAttributesAreNotMigratedToNewlyCreatedSessionIfMigrateAttributesIsFalse() throws Exception {
        MockHttpServletRequest request = createMockRequest();
        HttpSession oldSession = request.getSession();
        MockFilterConfig config = new MockFilterConfig(null, null);
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        MockAbstractProcessingFilter filter = new MockAbstractProcessingFilter(true);
        filter.setInvalidateSessionOnSuccessfulAuthentication(true);
        filter.setMigrateInvalidatedSessionAttributes(false);
        successHandler.setDefaultTargetUrl("http://monkeymachine.co.uk/");
        filter.setAuthenticationSuccessHandler(successHandler);

        executeFilterInContainerSimulator(config, filter, request, response, chain);

        HttpSession newSession = request.getSession();
        assertFalse(newSession.getId().equals(oldSession.getId()));
        assertNull(newSession.getAttribute("test"));
    }

    /**
     * SEC-571
     */
    public void testNoSessionIsCreatedIfAllowSessionCreationIsFalse() throws Exception {
        MockHttpServletRequest request = createMockRequest();

        MockFilterConfig config = new MockFilterConfig(null, null);
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Reject authentication, so exception would normally be stored in session
        MockAbstractProcessingFilter filter = new MockAbstractProcessingFilter(false);
        filter.setAllowSessionCreation(false);
        filter.setAuthenticationFailureHandler(failureHandler);
        successHandler.setDefaultTargetUrl("http://monkeymachine.co.uk/");
        filter.setAuthenticationSuccessHandler(successHandler);

        executeFilterInContainerSimulator(config, filter, request, response, chain);

        assertNull(request.getSession(false));
    }

    /**
     * SEC-462
     */
    public void testLoginErrorWithNoFailureUrlSendsUnauthorizedStatus() throws Exception {
        MockHttpServletRequest request = createMockRequest();

        MockFilterConfig config = new MockFilterConfig(null, null);
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        MockAbstractProcessingFilter filter = new MockAbstractProcessingFilter(false);
        successHandler.setDefaultTargetUrl("http://monkeymachine.co.uk/");
        filter.setAuthenticationSuccessHandler(successHandler);

        executeFilterInContainerSimulator(config, filter, request, response, chain);

        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
    }

    /**
     * SEC-462
     */
    public void testServerSideRedirectForwardsToFailureUrl() throws Exception {
        MockHttpServletRequest request = createMockRequest();

        MockFilterConfig config = new MockFilterConfig(null, null);
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        MockAbstractProcessingFilter filter = new MockAbstractProcessingFilter(false);
        successHandler.setDefaultTargetUrl("http://monkeymachine.co.uk/");
        filter.setAuthenticationSuccessHandler(successHandler);
        filter.setAuthenticationFailureHandler(failureHandler);
        failureHandler.setUseForward(true);
        failureHandler.setDefaultFailureUrl("/error");

        executeFilterInContainerSimulator(config, filter, request, response, chain);

        assertEquals("/error", response.getForwardedUrl());
    }

    /**
     * SEC-213
     */
    public void testTargetUrlParameterIsUsedIfPresent() throws Exception {
        MockHttpServletRequest request = createMockRequest();
        request.setParameter("targetUrl", "/target");

        MockFilterConfig config = new MockFilterConfig(null, null);
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        MockAbstractProcessingFilter filter = new MockAbstractProcessingFilter(true);
        filter.setAuthenticationSuccessHandler(successHandler);
        successHandler.setDefaultTargetUrl("http://monkeymachine.co.uk/");
        successHandler.setTargetUrlParameter("targetUrl");
        filter.setAuthenticationFailureHandler(failureHandler);

        executeFilterInContainerSimulator(config, filter, request, response, chain);

        assertEquals("/mycontext/target", response.getRedirectedUrl());
    }


    //~ Inner Classes ==================================================================================================

    private class MockAbstractProcessingFilter extends AbstractProcessingFilter {
        private AuthenticationException exceptionToThrow;
        private boolean grantAccess;

        public MockAbstractProcessingFilter(boolean grantAccess) {
            this();
            setRememberMeServices(new NullRememberMeServices());
            this.grantAccess = grantAccess;
            this.exceptionToThrow = new BadCredentialsException("Mock requested to do so");
        }

        public MockAbstractProcessingFilter(AuthenticationException exceptionToThrow) {
            this();
            setRememberMeServices(new NullRememberMeServices());
            this.grantAccess = false;
            this.exceptionToThrow = exceptionToThrow;
        }

        private MockAbstractProcessingFilter() {
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

        public int getOrder() {
            return 0;
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
