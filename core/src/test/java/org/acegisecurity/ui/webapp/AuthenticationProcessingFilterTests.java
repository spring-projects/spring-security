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

package net.sf.acegisecurity.ui.webapp;

import junit.framework.TestCase;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.MockFilterConfig;
import net.sf.acegisecurity.MockHttpServletRequest;
import net.sf.acegisecurity.MockHttpServletResponse;
import net.sf.acegisecurity.MockHttpSession;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


/**
 * Tests {@link AuthenticationProcessingFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AuthenticationProcessingFilterTests extends TestCase {
    //~ Constructors ===========================================================

    public AuthenticationProcessingFilterTests() {
        super();
    }

    public AuthenticationProcessingFilterTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(AuthenticationProcessingFilterTests.class);
    }

    public void testDoFilterWithNonHttpServletRequestDetected()
        throws Exception {
        AuthenticationProcessingFilter filter = new AuthenticationProcessingFilter();

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
        AuthenticationProcessingFilter filter = new AuthenticationProcessingFilter();

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
        MockHttpServletRequest request = new MockHttpServletRequest(null,
                new MockHttpSession());
        request.setContextPath("/myApp");
        request.setParameter(AuthenticationProcessingFilter.ACEGI_SECURITY_FORM_USERNAME_KEY,
            "marissa");
        request.setParameter(AuthenticationProcessingFilter.ACEGI_SECURITY_FORM_PASSWORD_KEY,
            "WRONG_PASSWORD");
        request.setServletPath("/j_acegi_security_check");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("appContextLocation",
            "net/sf/acegisecurity/ui/webapp/filtertest-valid.xml");
        config.setInitParmeter("defaultTargetUrl", "/");
        config.setInitParmeter("authenticationFailureUrl", "/failed.jsp");

        // Setup our expectation that the filter chain will not be invoked, as we redirect to authenticationFailureUrl
        MockFilterChain chain = new MockFilterChain(false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        AuthenticationProcessingFilter filter = new AuthenticationProcessingFilter();
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);
        System.out.println(response.getRedirect());
        assertEquals("/myApp/failed.jsp", response.getRedirect());
        assertTrue(request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY) == null);
    }

    public void testFilterProcessesUrlVariationsRespected()
        throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest(null,
                new MockHttpSession());
        request.setParameter(AuthenticationProcessingFilter.ACEGI_SECURITY_FORM_USERNAME_KEY,
            "marissa");
        request.setParameter(AuthenticationProcessingFilter.ACEGI_SECURITY_FORM_PASSWORD_KEY,
            "koala");
        request.setServletPath("/j_my_security_check");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("appContextLocation",
            "net/sf/acegisecurity/ui/webapp/filtertest-valid.xml");
        config.setInitParmeter("defaultTargetUrl", "/");
        config.setInitParmeter("authenticationFailureUrl", "/failed.jsp");
        config.setInitParmeter("filterProcessesUrl", "/j_my_security_check");

        // Setup our expectation that the filter chain will not be invoked, as we redirect to defaultTargetUrl
        MockFilterChain chain = new MockFilterChain(false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        AuthenticationProcessingFilter filter = new AuthenticationProcessingFilter();
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);
        assertEquals("/", response.getRedirect());
        assertTrue(request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY) != null);
        assertEquals("marissa",
            ((Authentication) request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY)).getPrincipal()
             .toString());
    }

    public void testIgnoresAnyServletPathOtherThanFilterProcessesUrl()
        throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest(null,
                new MockHttpSession());
        request.setServletPath("/j_some_other_url");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("appContextLocation",
            "net/sf/acegisecurity/ui/webapp/filtertest-valid.xml");
        config.setInitParmeter("defaultTargetUrl", "/");
        config.setInitParmeter("authenticationFailureUrl", "/failed.jsp");

        // Setup our expectation that the filter chain will be invoked, as should just proceed with chain
        MockFilterChain chain = new MockFilterChain(true);

        // Test
        AuthenticationProcessingFilter filter = new AuthenticationProcessingFilter();
        executeFilterInContainerSimulator(config, filter, request,
            new MockHttpServletResponse(), chain);
    }

    public void testNormalOperationWithDefaultFilterProcessesUrl()
        throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest(null,
                new MockHttpSession());
        request.setParameter(AuthenticationProcessingFilter.ACEGI_SECURITY_FORM_USERNAME_KEY,
            "marissa");
        request.setParameter(AuthenticationProcessingFilter.ACEGI_SECURITY_FORM_PASSWORD_KEY,
            "koala");
        request.setServletPath("/j_acegi_security_check");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("appContextLocation",
            "net/sf/acegisecurity/ui/webapp/filtertest-valid.xml");
        config.setInitParmeter("defaultTargetUrl", "/");
        config.setInitParmeter("authenticationFailureUrl", "/failed.jsp");

        // Setup our expectation that the filter chain will not be invoked, as we redirect to defaultTargetUrl
        MockFilterChain chain = new MockFilterChain(false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        AuthenticationProcessingFilter filter = new AuthenticationProcessingFilter();
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);
        assertEquals("/", response.getRedirect());
        assertTrue(request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY) != null);
        assertEquals("marissa",
            ((Authentication) request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY)).getPrincipal()
             .toString());
    }

    public void testNullPasswordHandledGracefully() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest(null,
                new MockHttpSession());
        request.setParameter(AuthenticationProcessingFilter.ACEGI_SECURITY_FORM_USERNAME_KEY,
            "marissa");
        request.setParameter(AuthenticationProcessingFilter.ACEGI_SECURITY_FORM_PASSWORD_KEY,
            null);
        request.setServletPath("/j_acegi_security_check");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("appContextLocation",
            "net/sf/acegisecurity/ui/webapp/filtertest-valid.xml");
        config.setInitParmeter("defaultTargetUrl", "/");
        config.setInitParmeter("authenticationFailureUrl", "/failed.jsp");

        // Setup our expectation that the filter chain will not be invoked, as we redirect to defaultTargetUrl
        MockFilterChain chain = new MockFilterChain(false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        AuthenticationProcessingFilter filter = new AuthenticationProcessingFilter();
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);
        assertEquals("/failed.jsp", response.getRedirect());
        assertTrue(request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY) == null);
    }

    public void testNullUsernameHandledGracefully() throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest(null,
                new MockHttpSession());
        request.setParameter(AuthenticationProcessingFilter.ACEGI_SECURITY_FORM_USERNAME_KEY,
            null);
        request.setParameter(AuthenticationProcessingFilter.ACEGI_SECURITY_FORM_PASSWORD_KEY,
            "koala");
        request.setServletPath("/j_acegi_security_check");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("appContextLocation",
            "net/sf/acegisecurity/ui/webapp/filtertest-valid.xml");
        config.setInitParmeter("defaultTargetUrl", "/");
        config.setInitParmeter("authenticationFailureUrl", "/failed.jsp");

        // Setup our expectation that the filter chain will not be invoked, as we redirect to defaultTargetUrl
        MockFilterChain chain = new MockFilterChain(false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        AuthenticationProcessingFilter filter = new AuthenticationProcessingFilter();
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);
        assertEquals("/failed.jsp", response.getRedirect());
        assertTrue(request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY) == null);
    }

    public void testStartupDetectsInvalidAppContextLocation()
        throws Exception {
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("defaultTargetUrl", "/");
        config.setInitParmeter("authenticationFailureUrl", "/failed.jsp");
        config.setInitParmeter("appContextLocation",
            "net/sf/acegisecurity/ui/webapp/filtertest-invalid.xml");

        AuthenticationProcessingFilter filter = new AuthenticationProcessingFilter();

        try {
            filter.init(config);
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertEquals("Bean context must contain at least one bean of type AuthenticationManager",
                expected.getMessage());
        }
    }

    public void testStartupDetectsMissingAppContext() throws Exception {
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("defaultTargetUrl", "/");
        config.setInitParmeter("authenticationFailureUrl", "/failed.jsp");

        AuthenticationProcessingFilter filter = new AuthenticationProcessingFilter();

        try {
            filter.init(config);
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertTrue(expected.getMessage().startsWith("Error obtaining/creating ApplicationContext for config."));
        }

        config.setInitParmeter("appContextLocation", "");

        try {
            filter.init(config);
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertTrue(expected.getMessage().startsWith("Error obtaining/creating ApplicationContext for config."));
        }
    }

    public void testStartupDetectsMissingAuthenticationFailureUrl()
        throws Exception {
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("appContextLocation",
            "net/sf/acegisecurity/ui/webapp/filtertest-valid.xml");
        config.setInitParmeter("defaultTargetUrl", "/");

        AuthenticationProcessingFilter filter = new AuthenticationProcessingFilter();

        try {
            filter.init(config);
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertEquals("authenticationFailureUrl must be specified",
                expected.getMessage());
        }

        config.setInitParmeter("authenticationFailureUrl", "");

        try {
            filter.init(config);
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertEquals("authenticationFailureUrl must be specified",
                expected.getMessage());
        }
    }

    public void testStartupDetectsMissingDefaultTargetUrl()
        throws Exception {
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("authenticationFailureUrl", "/failed.jsp");
        config.setInitParmeter("appContextLocation",
            "net/sf/acegisecurity/ui/webapp/filtertest-valid.xml");

        AuthenticationProcessingFilter filter = new AuthenticationProcessingFilter();

        try {
            filter.init(config);
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertEquals("defaultTargetUrl must be specified",
                expected.getMessage());
        }

        config.setInitParmeter("defaultTargetUrl", "");

        try {
            filter.init(config);
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertEquals("defaultTargetUrl must be specified",
                expected.getMessage());
        }
    }

    public void testStartupDetectsMissingInvalidAppContextLocation()
        throws Exception {
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("defaultTargetUrl", "/");
        config.setInitParmeter("authenticationFailureUrl", "/failed.jsp");
        config.setInitParmeter("appContextLocation", "DOES_NOT_EXIST");

        AuthenticationProcessingFilter filter = new AuthenticationProcessingFilter();

        try {
            filter.init(config);
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertTrue(expected.getMessage().startsWith("Cannot locate"));
        }
    }

    public void testSuccessLoginThenFailureLoginResultsInSessionLoosingToken()
        throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest(null,
                new MockHttpSession());
        request.setParameter(AuthenticationProcessingFilter.ACEGI_SECURITY_FORM_USERNAME_KEY,
            "marissa");
        request.setParameter(AuthenticationProcessingFilter.ACEGI_SECURITY_FORM_PASSWORD_KEY,
            "koala");
        request.setServletPath("/j_acegi_security_check");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("appContextLocation",
            "net/sf/acegisecurity/ui/webapp/filtertest-valid.xml");
        config.setInitParmeter("defaultTargetUrl", "/");
        config.setInitParmeter("authenticationFailureUrl", "/failed.jsp");

        // Setup our expectation that the filter chain will not be invoked, as we redirect to authenticationFailureUrl
        MockFilterChain chain = new MockFilterChain(false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        AuthenticationProcessingFilter filter = new AuthenticationProcessingFilter();
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);
        assertEquals("/", response.getRedirect());
        assertTrue(request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY) != null);

        // Now try again with a wrong password
        MockHttpServletRequest request2 = new MockHttpServletRequest(null,
                new MockHttpSession());
        request2.setParameter(AuthenticationProcessingFilter.ACEGI_SECURITY_FORM_USERNAME_KEY,
            "marissa");
        request2.setParameter(AuthenticationProcessingFilter.ACEGI_SECURITY_FORM_PASSWORD_KEY,
            "WRONG_PASSWORD");
        request2.setServletPath("/j_acegi_security_check");

        executeFilterInContainerSimulator(config, filter, request2, response,
            chain);
        assertTrue(request2.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY) == null);
    }

    public void testSuccessfulAuthenticationCausesRedirectToSessionSpecifiedUrl()
        throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest(null,
                new MockHttpSession());
        request.setParameter(AuthenticationProcessingFilter.ACEGI_SECURITY_FORM_USERNAME_KEY,
            "marissa");
        request.setParameter(AuthenticationProcessingFilter.ACEGI_SECURITY_FORM_PASSWORD_KEY,
            "koala");
        request.setServletPath("/j_acegi_security_check");
        request.getSession().setAttribute(AuthenticationProcessingFilter.ACEGI_SECURITY_TARGET_URL_KEY,
            "/my-destination");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("appContextLocation",
            "net/sf/acegisecurity/ui/webapp/filtertest-valid.xml");
        config.setInitParmeter("defaultTargetUrl", "/");
        config.setInitParmeter("authenticationFailureUrl", "/failed.jsp");

        // Setup our expectation that the filter chain will not be invoked, as we redirect to defaultTargetUrl
        MockFilterChain chain = new MockFilterChain(false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        AuthenticationProcessingFilter filter = new AuthenticationProcessingFilter();
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
