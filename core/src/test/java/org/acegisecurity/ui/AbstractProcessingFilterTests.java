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

package net.sf.acegisecurity.ui;

import junit.framework.TestCase;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationException;
import net.sf.acegisecurity.BadCredentialsException;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.MockAuthenticationManager;
import net.sf.acegisecurity.MockFilterConfig;
import net.sf.acegisecurity.MockHttpServletRequest;
import net.sf.acegisecurity.MockHttpServletResponse;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import net.sf.acegisecurity.ui.webapp.HttpSessionIntegrationFilter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;


/**
 * Tests {@link AbstractProcessingFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AbstractProcessingFilterTests extends TestCase {
    //~ Constructors ===========================================================

    public AbstractProcessingFilterTests() {
        super();
    }

    public AbstractProcessingFilterTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(AbstractProcessingFilterTests.class);
    }

    public void testDoFilterWithNonHttpServletRequestDetected()
        throws Exception {
        AbstractProcessingFilter filter = new MockAbstractProcessingFilter();

        try {
            filter.doFilter(null, new MockHttpServletResponse(),
                new MockFilterChain());
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertEquals("Can only process HttpServletRequest",
                expected.getMessage());
        }
    }

    public void testDoFilterWithNonHttpServletResponseDetected()
        throws Exception {
        AbstractProcessingFilter filter = new MockAbstractProcessingFilter();

        try {
            filter.doFilter(new MockHttpServletRequest(null, null), null,
                new MockFilterChain());
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertEquals("Can only process HttpServletResponse",
                expected.getMessage());
        }
    }

    public void testFailedAuthenticationRedirectsAppropriately()
        throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest("");
        request.setServletPath("/j_mock_post");
        request.setRequestURL("http://www.example.com/mycontext/j_mock_post");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();

        // Setup our expectation that the filter chain will not be invoked, as we redirect to authenticationFailureUrl
        MockFilterChain chain = new MockFilterChain(false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Setup our test object, to deny access
        MockAbstractProcessingFilter filter = new MockAbstractProcessingFilter(false);
        filter.setAuthenticationFailureUrl("/myApp/failed.jsp");

        // Test
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);
        assertEquals("/myApp/failed.jsp", response.getRedirect());
        assertTrue(request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY) == null);
    }

    public void testFilterProcessesUrlVariationsRespected()
        throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest("");
        request.setServletPath("/j_OTHER_LOCATION");
        request.setRequestURL(
            "http://www.example.com/mycontext/j_OTHER_LOCATION");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();

        // Setup our expectation that the filter chain will not be invoked, as we redirect to defaultTargetUrl
        MockFilterChain chain = new MockFilterChain(false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Setup our test object, to grant access
        MockAbstractProcessingFilter filter = new MockAbstractProcessingFilter(true);
        filter.setFilterProcessesUrl("/j_OTHER_LOCATION");
        filter.setDefaultTargetUrl("/logged_in.jsp");

        // Test
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);
        assertEquals("/logged_in.jsp", response.getRedirect());
        assertTrue(request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY) != null);
        assertEquals("test",
            ((Authentication) request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY)).getPrincipal()
             .toString());
    }

    public void testGettersSetters() {
        AbstractProcessingFilter filter = new MockAbstractProcessingFilter();
        filter.setAuthenticationFailureUrl("/x");
        assertEquals("/x", filter.getAuthenticationFailureUrl());

        filter.setAuthenticationManager(new MockAuthenticationManager());
        assertTrue(filter.getAuthenticationManager() != null);

        filter.setDefaultTargetUrl("/default");
        assertEquals("/default", filter.getDefaultTargetUrl());

        filter.setFilterProcessesUrl("/p");
        assertEquals("/p", filter.getFilterProcessesUrl());
    }

    public void testIgnoresAnyServletPathOtherThanFilterProcessesUrl()
        throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest("");
        request.setServletPath("/some.file.html");
        request.setRequestURL("http://www.example.com/mycontext/some.file.html");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();

        // Setup our expectation that the filter chain will be invoked, as our request is for a page the filter isn't monitoring
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Setup our test object, to deny access
        MockAbstractProcessingFilter filter = new MockAbstractProcessingFilter(false);

        // Test
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);
    }

    public void testNormalOperationWithDefaultFilterProcessesUrl()
        throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest("");
        request.setServletPath("/j_mock_post");
        request.setRequestURL("http://www.example.com/mycontext/j_mock_post");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();

        // Setup our expectation that the filter chain will not be invoked, as we redirect to defaultTargetUrl
        MockFilterChain chain = new MockFilterChain(false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Setup our test object, to grant access
        MockAbstractProcessingFilter filter = new MockAbstractProcessingFilter(true);
        filter.setFilterProcessesUrl("/j_mock_post");
        filter.setDefaultTargetUrl("/logged_in.jsp");
        filter.setAuthenticationFailureUrl("/failure.jsp");
        filter.setAuthenticationManager(new MockAuthenticationManager(true));
        filter.afterPropertiesSet();

        // Test
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);
        assertEquals("/logged_in.jsp", response.getRedirect());
        assertTrue(request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY) != null);
        assertEquals("test",
            ((Authentication) request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY)).getPrincipal()
             .toString());
    }

    public void testStartupDetectsInvalidAuthenticationFailureUrl()
        throws Exception {
        AbstractProcessingFilter filter = new MockAbstractProcessingFilter();
        filter.setAuthenticationManager(new MockAuthenticationManager());
        filter.setDefaultTargetUrl("/");
        filter.setFilterProcessesUrl("/j_acegi_security_check");

        try {
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("authenticationFailureUrl must be specified",
                expected.getMessage());
        }
    }

    public void testStartupDetectsInvalidAuthenticationManager()
        throws Exception {
        AbstractProcessingFilter filter = new MockAbstractProcessingFilter();
        filter.setAuthenticationFailureUrl("/failed.jsp");
        filter.setDefaultTargetUrl("/");
        filter.setFilterProcessesUrl("/j_acegi_security_check");

        try {
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("authenticationManager must be specified",
                expected.getMessage());
        }
    }

    public void testStartupDetectsInvalidDefaultTargetUrl()
        throws Exception {
        AbstractProcessingFilter filter = new MockAbstractProcessingFilter();
        filter.setAuthenticationFailureUrl("/failed.jsp");
        filter.setAuthenticationManager(new MockAuthenticationManager());
        filter.setFilterProcessesUrl("/j_acegi_security_check");

        try {
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("defaultTargetUrl must be specified",
                expected.getMessage());
        }
    }

    public void testStartupDetectsInvalidFilterProcessesUrl()
        throws Exception {
        AbstractProcessingFilter filter = new MockAbstractProcessingFilter();
        filter.setAuthenticationFailureUrl("/failed.jsp");
        filter.setAuthenticationManager(new MockAuthenticationManager());
        filter.setDefaultTargetUrl("/");
        filter.setFilterProcessesUrl(null);

        try {
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("filterProcessesUrl must be specified",
                expected.getMessage());
        }
    }

    public void testSuccessLoginThenFailureLoginResultsInSessionLoosingToken()
        throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest("");
        request.setServletPath("/j_mock_post");
        request.setRequestURL("http://www.example.com/mycontext/j_mock_post");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();

        // Setup our expectation that the filter chain will not be invoked, as we redirect to defaultTargetUrl
        MockFilterChain chain = new MockFilterChain(false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Setup our test object, to grant access
        MockAbstractProcessingFilter filter = new MockAbstractProcessingFilter(true);
        filter.setFilterProcessesUrl("/j_mock_post");
        filter.setDefaultTargetUrl("/logged_in.jsp");

        // Test
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);
        assertEquals("/logged_in.jsp", response.getRedirect());
        assertTrue(request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY) != null);
        assertEquals("test",
            ((Authentication) request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY)).getPrincipal()
             .toString());

        // Now try again but this time have filter deny access
        // Setup our HTTP request
        // Setup our expectation that the filter chain will not be invoked, as we redirect to authenticationFailureUrl
        chain = new MockFilterChain(false);
        response = new MockHttpServletResponse();

        // Setup our test object, to deny access
        filter = new MockAbstractProcessingFilter(false);
        filter.setFilterProcessesUrl("/j_mock_post");
        filter.setAuthenticationFailureUrl("/failed.jsp");

        // Test
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);
        assertTrue(request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY) == null);
    }

    public void testSuccessfulAuthenticationCausesRedirectToSessionSpecifiedUrl()
        throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest("");
        request.setServletPath("/j_mock_post");
        request.setRequestURL("http://www.example.com/mycontext/j_mock_post");
        request.getSession().setAttribute(AbstractProcessingFilter.ACEGI_SECURITY_TARGET_URL_KEY,
            "/my-destination");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();

        // Setup our expectation that the filter chain will be invoked, as we want to go to the location requested in the session
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Setup our test object, to grant access
        MockAbstractProcessingFilter filter = new MockAbstractProcessingFilter(true);
        filter.setFilterProcessesUrl("/j_mock_post");

        // Test
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);
        assertEquals("/my-destination", response.getRedirect());
        assertTrue(request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY) != null);
    }

    private void executeFilterInContainerSimulator(FilterConfig filterConfig,
        Filter filter, ServletRequest request, ServletResponse response,
        FilterChain filterChain) throws ServletException, IOException {
        filter.init(filterConfig);
        filter.doFilter(request, response, filterChain);
        filter.destroy();
    }

    //~ Inner Classes ==========================================================

    private class MockAbstractProcessingFilter extends AbstractProcessingFilter {
        private boolean grantAccess;

        public MockAbstractProcessingFilter(boolean grantAccess) {
            this.grantAccess = grantAccess;
        }

        private MockAbstractProcessingFilter() {
            super();
        }

        public String getDefaultFilterProcessesUrl() {
            return "/j_mock_post";
        }

        public Authentication attemptAuthentication(HttpServletRequest request)
            throws AuthenticationException {
            if (grantAccess) {
                return new UsernamePasswordAuthenticationToken("test", "test",
                    new GrantedAuthority[] {new GrantedAuthorityImpl("TEST")});
            } else {
                throw new BadCredentialsException("Mock requested to do so");
            }
        }

        public void init(FilterConfig arg0) throws ServletException {}
    }

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
}
