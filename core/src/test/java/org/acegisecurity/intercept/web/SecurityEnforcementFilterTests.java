/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package org.acegisecurity.intercept.web;

import junit.framework.TestCase;

import org.acegisecurity.AccessDeniedException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.MockAuthenticationEntryPoint;
import org.acegisecurity.MockPortResolver;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.context.SecurityContextImpl;
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationToken;
import org.acegisecurity.ui.webapp.AuthenticationProcessingFilter;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


/**
 * Tests {@link SecurityEnforcementFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class SecurityEnforcementFilterTests extends TestCase {
    //~ Constructors ===========================================================

    public SecurityEnforcementFilterTests() {
        super();
    }

    public SecurityEnforcementFilterTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(SecurityEnforcementFilterTests.class);
    }

    public void testAccessDeniedWhenAnonymous() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/secure/page.html");
        request.setServerPort(80);
        request.setScheme("http");
        request.setServerName("www.example.com");
        request.setContextPath("/mycontext");
        request.setRequestURI("/mycontext/secure/page.html");

        // Setup our expectation that the filter chain will not be invoked, as access is denied
        MockFilterChain chain = new MockFilterChain(false);

        // Setup the FilterSecurityInterceptor thrown an access denied exception
        MockFilterSecurityInterceptor interceptor = new MockFilterSecurityInterceptor(true,
                false, false, false);

        // Setup SecurityContextHolder, as filter needs to check if user is anonymous
        SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken(
                "ignored", "ignored",
                new GrantedAuthority[] {new GrantedAuthorityImpl("IGNORED")}));

        // Test
        SecurityEnforcementFilter filter = new SecurityEnforcementFilter();
        filter.setFilterSecurityInterceptor(interceptor);
        filter.setAuthenticationEntryPoint(new MockAuthenticationEntryPoint(
                "/login.jsp"));

        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);
        assertEquals("/mycontext/login.jsp", response.getRedirectedUrl());
        assertEquals("http://www.example.com/mycontext/secure/page.html",
            request.getSession().getAttribute(AuthenticationProcessingFilter.ACEGI_SECURITY_TARGET_URL_KEY));
    }

    public void testAccessDeniedWhenNonAnonymous() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/secure/page.html");

        // Setup our expectation that the filter chain will not be invoked, as access is denied
        MockFilterChain chain = new MockFilterChain(false);

        // Setup the FilterSecurityInterceptor thrown an access denied exception
        MockFilterSecurityInterceptor interceptor = new MockFilterSecurityInterceptor(true,
                false, false, false);

        // Setup SecurityContextHolder, as filter needs to check if user is anonymous
        SecurityContextHolder.getContext().setAuthentication(null);

        // Test
        SecurityEnforcementFilter filter = new SecurityEnforcementFilter();
        filter.setFilterSecurityInterceptor(interceptor);
        filter.setAuthenticationEntryPoint(new MockAuthenticationEntryPoint(
                "/login.jsp"));

        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);
        assertEquals(403, response.getStatus());
        assertEquals(AccessDeniedException.class,
            request.getSession()
                   .getAttribute(SecurityEnforcementFilter.ACEGI_SECURITY_ACCESS_DENIED_EXCEPTION_KEY)
                   .getClass());
    }

    public void testDoFilterWithNonHttpServletRequestDetected()
        throws Exception {
        SecurityEnforcementFilter filter = new SecurityEnforcementFilter();

        try {
            filter.doFilter(null, new MockHttpServletResponse(),
                new MockFilterChain());
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertEquals("HttpServletRequest required", expected.getMessage());
        }
    }

    public void testDoFilterWithNonHttpServletResponseDetected()
        throws Exception {
        SecurityEnforcementFilter filter = new SecurityEnforcementFilter();

        try {
            filter.doFilter(new MockHttpServletRequest(null, null), null,
                new MockFilterChain());
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertEquals("HttpServletResponse required", expected.getMessage());
        }
    }

    public void testGettersSetters() {
        SecurityEnforcementFilter filter = new SecurityEnforcementFilter();
        filter.setFilterSecurityInterceptor(new MockFilterSecurityInterceptor(
                false, false, false, false));
        assertTrue(filter.getFilterSecurityInterceptor() != null);

        filter.setAuthenticationEntryPoint(new MockAuthenticationEntryPoint(
                "/login.jsp"));
        assertTrue(filter.getAuthenticationEntryPoint() != null);

        filter.setPortResolver(new MockPortResolver(80, 443));
        assertTrue(filter.getPortResolver() != null);
    }

    public void testRedirectedToLoginFormAndSessionShowsOriginalTargetWhenAuthenticationException()
        throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/secure/page.html");
        request.setServerPort(80);
        request.setScheme("http");
        request.setServerName("www.example.com");
        request.setContextPath("/mycontext");
        request.setRequestURI("/mycontext/secure/page.html");

        // Setup our expectation that the filter chain will not be invoked, as access is denied
        MockFilterChain chain = new MockFilterChain(false);

        // Setup the FilterSecurityInterceptor thrown an authentication failure exceptions
        MockFilterSecurityInterceptor interceptor = new MockFilterSecurityInterceptor(false,
                true, false, false);

        // Test
        SecurityEnforcementFilter filter = new SecurityEnforcementFilter();
        filter.setFilterSecurityInterceptor(interceptor);
        filter.setAuthenticationEntryPoint(new MockAuthenticationEntryPoint(
                "/login.jsp"));
        filter.setPortResolver(new MockPortResolver(80, 443));
        filter.afterPropertiesSet();

        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);
        assertEquals("/mycontext/login.jsp", response.getRedirectedUrl());
        assertEquals("http://www.example.com/mycontext/secure/page.html",
            request.getSession().getAttribute(AuthenticationProcessingFilter.ACEGI_SECURITY_TARGET_URL_KEY));
    }

    public void testRedirectedToLoginFormAndSessionShowsOriginalTargetWithExoticPortWhenAuthenticationException()
        throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/secure/page.html");
        request.setServerPort(8080);
        request.setScheme("http");
        request.setServerName("www.example.com");
        request.setContextPath("/mycontext");
        request.setRequestURI("/mycontext/secure/page.html");

        // Setup our expectation that the filter chain will not be invoked, as access is denied
        MockFilterChain chain = new MockFilterChain(false);

        // Setup the FilterSecurityInterceptor thrown an authentication failure exceptions
        MockFilterSecurityInterceptor interceptor = new MockFilterSecurityInterceptor(false,
                true, false, false);

        // Test
        SecurityEnforcementFilter filter = new SecurityEnforcementFilter();
        filter.setFilterSecurityInterceptor(interceptor);
        filter.setAuthenticationEntryPoint(new MockAuthenticationEntryPoint(
                "/login.jsp"));
        filter.setPortResolver(new MockPortResolver(8080, 8443));
        filter.afterPropertiesSet();

        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);
        assertEquals("/mycontext/login.jsp", response.getRedirectedUrl());
        assertEquals("http://www.example.com:8080/mycontext/secure/page.html",
            request.getSession().getAttribute(AuthenticationProcessingFilter.ACEGI_SECURITY_TARGET_URL_KEY));
    }

    public void testStartupDetectsMissingAuthenticationEntryPoint()
        throws Exception {
        SecurityEnforcementFilter filter = new SecurityEnforcementFilter();
        filter.setFilterSecurityInterceptor(new MockFilterSecurityInterceptor(
                false, false, false, false));

        try {
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("authenticationEntryPoint must be specified",
                expected.getMessage());
        }
    }

    public void testStartupDetectsMissingFilterSecurityInterceptor()
        throws Exception {
        SecurityEnforcementFilter filter = new SecurityEnforcementFilter();
        filter.setAuthenticationEntryPoint(new MockAuthenticationEntryPoint(
                "/login.jsp"));

        try {
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("filterSecurityInterceptor must be specified",
                expected.getMessage());
        }
    }

    public void testStartupDetectsMissingPortResolver()
        throws Exception {
        SecurityEnforcementFilter filter = new SecurityEnforcementFilter();
        filter.setFilterSecurityInterceptor(new MockFilterSecurityInterceptor(
                false, false, false, false));
        filter.setAuthenticationEntryPoint(new MockAuthenticationEntryPoint(
                "/login.jsp"));
        filter.setPortResolver(null);

        try {
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("portResolver must be specified", expected.getMessage());
        }
    }

    public void testSuccessfulAccessGrant() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/secure/page.html");

        // Setup our expectation that the filter chain will be invoked, as access is granted
        MockFilterChain chain = new MockFilterChain(true);

        // Setup the FilterSecurityInterceptor to not thrown any exceptions
        MockFilterSecurityInterceptor interceptor = new MockFilterSecurityInterceptor(false,
                false, false, false);

        // Test
        SecurityEnforcementFilter filter = new SecurityEnforcementFilter();
        filter.setFilterSecurityInterceptor(interceptor);
        filter.setAuthenticationEntryPoint(new MockAuthenticationEntryPoint(
                "/login.jsp"));

        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);
    }

    public void testSuccessfulStartupAndShutdownDown()
        throws Exception {
        SecurityEnforcementFilter filter = new SecurityEnforcementFilter();

        filter.init(null);
        filter.destroy();
        assertTrue(true);
    }

    public void testThrowIOException() throws Exception {
        SecurityEnforcementFilter filter = new SecurityEnforcementFilter();

        filter.setFilterSecurityInterceptor(new MockFilterSecurityInterceptor(
                false, false, false, true));

        filter.setAuthenticationEntryPoint(new MockAuthenticationEntryPoint(""));

        filter.afterPropertiesSet();

        try {
            filter.doFilter(new MockHttpServletRequest(),
                new MockHttpServletResponse(), new MockFilterChain(false));
            fail("Should have thrown IOException");
        } catch (IOException e) {
            assertNull("The IOException thrown should not have been wrapped",
                e.getCause());
        }
    }

    public void testThrowServletException() throws Exception {
        SecurityEnforcementFilter filter = new SecurityEnforcementFilter();

        filter.setFilterSecurityInterceptor(new MockFilterSecurityInterceptor(
                false, false, true, false));

        filter.setAuthenticationEntryPoint(new MockAuthenticationEntryPoint(""));

        filter.afterPropertiesSet();

        try {
            filter.doFilter(new MockHttpServletRequest(),
                new MockHttpServletResponse(), new MockFilterChain(false));
            fail("Should have thrown ServletException");
        } catch (ServletException e) {
            assertNull("The ServletException thrown should not have been wrapped",
                e.getCause());
        }
    }

    protected void tearDown() throws Exception {
        super.tearDown();
        SecurityContextHolder.setContext(new SecurityContextImpl());
    }

    //~ Inner Classes ==========================================================

    private class MockFilterChain implements FilterChain {
        private boolean expectToProceed;

        public MockFilterChain(boolean expectToProceed) {
            this.expectToProceed = expectToProceed;
        }

        private MockFilterChain() {
            super();
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

    private class MockFilterSecurityInterceptor
        extends FilterSecurityInterceptor {
        private boolean throwAccessDenied;
        private boolean throwAuthenticationFailure;
        private boolean throwIOException;
        private boolean throwServletException;

        public MockFilterSecurityInterceptor(boolean throwAccessDenied,
            boolean throwAuthenticationFailure, boolean throwServletException,
            boolean throwIOException) {
            this.throwAccessDenied = throwAccessDenied;
            this.throwAuthenticationFailure = throwAuthenticationFailure;
            this.throwServletException = throwServletException;
            this.throwIOException = throwIOException;
        }

        public void invoke(FilterInvocation fi) throws Throwable {
            if (throwAccessDenied) {
                throw new AccessDeniedException("As requested");
            }

            if (throwAuthenticationFailure) {
                throw new BadCredentialsException("As requested");
            }

            if (throwServletException) {
                throw new ServletException("As requested");
            }

            if (throwIOException) {
                throw new IOException("As requested");
            }

            fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
        }
    }
}
