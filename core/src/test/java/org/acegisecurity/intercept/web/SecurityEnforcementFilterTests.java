/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.intercept.web;

import junit.framework.TestCase;

import net.sf.acegisecurity.AccessDeniedException;
import net.sf.acegisecurity.BadCredentialsException;
import net.sf.acegisecurity.MockAuthenticationEntryPoint;
import net.sf.acegisecurity.MockHttpServletRequest;
import net.sf.acegisecurity.MockHttpServletResponse;
import net.sf.acegisecurity.MockHttpSession;
import net.sf.acegisecurity.ui.webapp.AuthenticationProcessingFilter;

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

    public void testAccessDeniedWhenAccessDeniedException()
        throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest(null,
                new MockHttpSession());
        request.setServletPath("/secure/page.html");

        // Setup our expectation that the filter chain will not be invoked, as access is denied
        MockFilterChain chain = new MockFilterChain(false);

        // Setup the FilterSecurityInterceptor thrown an access denied exception
        MockFilterSecurityInterceptor interceptor = new MockFilterSecurityInterceptor(true,
                false);

        // Test
        SecurityEnforcementFilter filter = new SecurityEnforcementFilter();
        filter.setFilterSecurityInterceptor(interceptor);
        filter.setAuthenticationEntryPoint(new MockAuthenticationEntryPoint(
                "/login.jsp"));

        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);
        assertEquals(403, response.getError());
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
                false, false));
        assertTrue(filter.getFilterSecurityInterceptor() != null);

        filter.setAuthenticationEntryPoint(new MockAuthenticationEntryPoint(
                "/login.jsp"));
        assertTrue(filter.getAuthenticationEntryPoint() != null);
    }

    public void testRedirectedToLoginFormAndSessionShowsOriginalTargetWhenAuthenticationException()
        throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest(null,
                new MockHttpSession());
        request.setServletPath("/secure/page.html");
        request.setRequestURL(
            "http://www.example.com/mycontext/secure/page.html");

        // Setup our expectation that the filter chain will not be invoked, as access is denied
        MockFilterChain chain = new MockFilterChain(false);

        // Setup the FilterSecurityInterceptor thrown an authentication failure exceptions
        MockFilterSecurityInterceptor interceptor = new MockFilterSecurityInterceptor(false,
                true);

        // Test
        SecurityEnforcementFilter filter = new SecurityEnforcementFilter();
        filter.setFilterSecurityInterceptor(interceptor);
        filter.setAuthenticationEntryPoint(new MockAuthenticationEntryPoint(
                "/login.jsp"));
        filter.afterPropertiesSet();

        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);
        assertEquals("/login.jsp", response.getRedirect());
        assertEquals("http://www.example.com/mycontext/secure/page.html",
            request.getSession().getAttribute(AuthenticationProcessingFilter.ACEGI_SECURITY_TARGET_URL_KEY));
    }

    public void testStartupDetectsMissingAuthenticationEntryPoint()
        throws Exception {
        SecurityEnforcementFilter filter = new SecurityEnforcementFilter();
        filter.setFilterSecurityInterceptor(new MockFilterSecurityInterceptor(
                false, false));

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

    public void testSuccessfulAccessGrant() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest(null,
                new MockHttpSession());
        request.setServletPath("/secure/page.html");

        // Setup our expectation that the filter chain will be invoked, as access is granted
        MockFilterChain chain = new MockFilterChain(true);

        // Setup the FilterSecurityInterceptor to not thrown any exceptions
        MockFilterSecurityInterceptor interceptor = new MockFilterSecurityInterceptor(false,
                false);

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

        public MockFilterSecurityInterceptor(boolean throwAccessDenied,
            boolean throwAuthenticationFailure) {
            this.throwAccessDenied = throwAccessDenied;
            this.throwAuthenticationFailure = throwAuthenticationFailure;
        }

        private MockFilterSecurityInterceptor() {
            super();
        }

        public void invoke(FilterInvocation fi) throws Throwable {
            if (throwAccessDenied) {
                throw new AccessDeniedException("As requested");
            }

            if (throwAuthenticationFailure) {
                throw new BadCredentialsException("As requested");
            }

            fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
        }
    }
}
