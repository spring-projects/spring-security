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

package net.sf.acegisecurity.ui.basicauth;

import junit.framework.TestCase;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.MockFilterConfig;
import net.sf.acegisecurity.MockHttpServletRequest;
import net.sf.acegisecurity.MockHttpServletResponse;
import net.sf.acegisecurity.MockHttpSession;
import net.sf.acegisecurity.ui.webapp.HttpSessionIntegrationFilter;

import org.apache.commons.codec.binary.Base64;

import java.io.IOException;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


/**
 * Tests {@link BasicProcessingFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class BasicProcessingFilterTests extends TestCase {
    //~ Constructors ===========================================================

    public BasicProcessingFilterTests() {
        super();
    }

    public BasicProcessingFilterTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(BasicProcessingFilterTests.class);
    }

    public void testDoFilterWithNonHttpServletRequestDetected()
        throws Exception {
        BasicProcessingFilter filter = new BasicProcessingFilter();

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
        BasicProcessingFilter filter = new BasicProcessingFilter();

        try {
            filter.doFilter(new MockHttpServletRequest(null, null), null,
                new MockFilterChain());
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertEquals("Can only process HttpServletResponse",
                expected.getMessage());
        }
    }

    public void testFilterIgnoresRequestsContainingNoAuthorizationHeader()
        throws Exception {
        // Setup our HTTP request
        Map headers = new HashMap();
        MockHttpServletRequest request = new MockHttpServletRequest(headers,
                null, new MockHttpSession());
        request.setServletPath("/some_file.html");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("contextConfigLocation",
            "net/sf/acegisecurity/ui/webapp/filtertest-valid.xml");

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        BasicProcessingFilter filter = new BasicProcessingFilter();
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);

        assertTrue(request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY) == null);
    }

    public void testInvalidBasicAuthorizationTokenIsIgnored()
        throws Exception {
        // Setup our HTTP request
        Map headers = new HashMap();
        String token = "NOT_A_VALID_TOKEN_AS_MISSING_COLON";
        headers.put("Authorization",
            "Basic " + new String(Base64.encodeBase64(token.getBytes())));

        MockHttpServletRequest request = new MockHttpServletRequest(headers,
                null, new MockHttpSession());
        request.setServletPath("/some_file.html");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("contextConfigLocation",
            "net/sf/acegisecurity/ui/webapp/filtertest-valid.xml");

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        BasicProcessingFilter filter = new BasicProcessingFilter();
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);

        assertTrue(request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY) == null);
    }

    public void testNormalOperation() throws Exception {
        // Setup our HTTP request
        Map headers = new HashMap();
        String token = "marissa:koala";
        headers.put("Authorization",
            "Basic " + new String(Base64.encodeBase64(token.getBytes())));

        MockHttpServletRequest request = new MockHttpServletRequest(headers,
                null, new MockHttpSession());
        request.setServletPath("/some_file.html");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("contextConfigLocation",
            "net/sf/acegisecurity/ui/webapp/filtertest-valid.xml");

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        BasicProcessingFilter filter = new BasicProcessingFilter();
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);

        assertTrue(request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY) != null);
        assertEquals("marissa",
            ((Authentication) request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY)).getPrincipal()
             .toString());
    }

    public void testOtherAuthorizationSchemeIsIgnored()
        throws Exception {
        // Setup our HTTP request
        Map headers = new HashMap();
        headers.put("Authorization", "SOME_OTHER_AUTHENTICATION_SCHEME");

        MockHttpServletRequest request = new MockHttpServletRequest(headers,
                null, new MockHttpSession());
        request.setServletPath("/some_file.html");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("contextConfigLocation",
            "net/sf/acegisecurity/ui/webapp/filtertest-valid.xml");

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        BasicProcessingFilter filter = new BasicProcessingFilter();
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);

        assertTrue(request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY) == null);
    }

    public void testStartupDetectsInvalidContextConfigLocation()
        throws Exception {
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("contextConfigLocation",
            "net/sf/acegisecurity/ui/webapp/filtertest-invalid.xml");

        BasicProcessingFilter filter = new BasicProcessingFilter();

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

        BasicProcessingFilter filter = new BasicProcessingFilter();

        try {
            filter.init(config);
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertTrue(expected.getMessage().startsWith("Error obtaining/creating ApplicationContext for config."));
        }

        config.setInitParmeter("contextConfigLocation", "");

        try {
            filter.init(config);
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertTrue(expected.getMessage().startsWith("Error obtaining/creating ApplicationContext for config."));
        }
    }

    public void testStartupDetectsMissingInvalidContextConfigLocation()
        throws Exception {
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("contextConfigLocation", "DOES_NOT_EXIST");

        BasicProcessingFilter filter = new BasicProcessingFilter();

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
        Map headers = new HashMap();
        String token = "marissa:koala";
        headers.put("Authorization",
            "Basic " + new String(Base64.encodeBase64(token.getBytes())));

        MockHttpServletRequest request = new MockHttpServletRequest(headers,
                null, new MockHttpSession());
        request.setServletPath("/some_file.html");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("contextConfigLocation",
            "net/sf/acegisecurity/ui/webapp/filtertest-valid.xml");

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        BasicProcessingFilter filter = new BasicProcessingFilter();
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);

        assertTrue(request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY) != null);
        assertEquals("marissa",
            ((Authentication) request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY)).getPrincipal()
             .toString());

        // NOW PERFORM FAILED AUTHENTICATION
        // Setup our HTTP request
        headers = new HashMap();
        token = "marissa:WRONG_PASSWORD";
        headers.put("Authorization",
            "Basic " + new String(Base64.encodeBase64(token.getBytes())));
        request = new MockHttpServletRequest(headers, null,
                new MockHttpSession());
        request.setServletPath("/some_file.html");

        // Setup our expectation that the filter chain will not be invoked, as we get a 403 forbidden response
        chain = new MockFilterChain(false);
        response = new MockHttpServletResponse();

        // Test
        filter = new BasicProcessingFilter();
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);

        assertTrue(request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY) == null);
        assertEquals(403, response.getError());
    }

    public void testWrongPasswordReturnsForbidden() throws Exception {
        // Setup our HTTP request
        Map headers = new HashMap();
        String token = "marissa:WRONG_PASSWORD";
        headers.put("Authorization",
            "Basic " + new String(Base64.encodeBase64(token.getBytes())));

        MockHttpServletRequest request = new MockHttpServletRequest(headers,
                null, new MockHttpSession());
        request.setServletPath("/some_file.html");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();
        config.setInitParmeter("contextConfigLocation",
            "net/sf/acegisecurity/ui/webapp/filtertest-valid.xml");

        // Setup our expectation that the filter chain will not be invoked, as we get a 403 forbidden response
        MockFilterChain chain = new MockFilterChain(false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        BasicProcessingFilter filter = new BasicProcessingFilter();
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);

        assertTrue(request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY) == null);
        assertEquals(403, response.getError());
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
