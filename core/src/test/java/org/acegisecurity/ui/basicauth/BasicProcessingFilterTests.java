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
import net.sf.acegisecurity.MockAuthenticationEntryPoint;
import net.sf.acegisecurity.MockAuthenticationManager;
import net.sf.acegisecurity.MockFilterConfig;
import net.sf.acegisecurity.MockHttpServletRequest;
import net.sf.acegisecurity.MockHttpServletResponse;
import net.sf.acegisecurity.MockHttpSession;
import net.sf.acegisecurity.ui.webapp.HttpSessionIntegrationFilter;

import org.apache.commons.codec.binary.Base64;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

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

        // Launch an application context and access our bean
        ApplicationContext ctx = new ClassPathXmlApplicationContext(
                "net/sf/acegisecurity/ui/basicauth/filtertest-valid.xml");
        BasicProcessingFilter filter = (BasicProcessingFilter) ctx.getBean(
                "basicProcessingFilter");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);

        assertTrue(request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY) == null);
    }

    public void testGettersSetters() {
        BasicProcessingFilter filter = new BasicProcessingFilter();
        filter.setAuthenticationManager(new MockAuthenticationManager());
        assertTrue(filter.getAuthenticationManager() != null);

        filter.setAuthenticationEntryPoint(new MockAuthenticationEntryPoint(
                "sx"));
        assertTrue(filter.getAuthenticationEntryPoint() != null);
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

        // Launch an application context and access our bean
        ApplicationContext ctx = new ClassPathXmlApplicationContext(
                "net/sf/acegisecurity/ui/basicauth/filtertest-valid.xml");
        BasicProcessingFilter filter = (BasicProcessingFilter) ctx.getBean(
                "basicProcessingFilter");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
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

        // Launch an application context and access our bean
        ApplicationContext ctx = new ClassPathXmlApplicationContext(
                "net/sf/acegisecurity/ui/basicauth/filtertest-valid.xml");
        BasicProcessingFilter filter = (BasicProcessingFilter) ctx.getBean(
                "basicProcessingFilter");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
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

        // Launch an application context and access our bean
        ApplicationContext ctx = new ClassPathXmlApplicationContext(
                "net/sf/acegisecurity/ui/basicauth/filtertest-valid.xml");
        BasicProcessingFilter filter = (BasicProcessingFilter) ctx.getBean(
                "basicProcessingFilter");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);

        assertTrue(request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY) == null);
    }

    public void testStartupDetectsMissingAuthenticationEntryPoint()
        throws Exception {
        try {
            BasicProcessingFilter filter = new BasicProcessingFilter();
            filter.setAuthenticationManager(new MockAuthenticationManager());
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("An AuthenticationEntryPoint is required",
                expected.getMessage());
        }
    }

    public void testStartupDetectsMissingAuthenticationManager()
        throws Exception {
        try {
            BasicProcessingFilter filter = new BasicProcessingFilter();
            filter.setAuthenticationEntryPoint(new MockAuthenticationEntryPoint(
                    "x"));
            filter.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("An AuthenticationManager is required",
                expected.getMessage());
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

        // Launch an application context and access our bean
        ApplicationContext ctx = new ClassPathXmlApplicationContext(
                "net/sf/acegisecurity/ui/basicauth/filtertest-valid.xml");
        BasicProcessingFilter filter = (BasicProcessingFilter) ctx.getBean(
                "basicProcessingFilter");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();

        // Setup our expectation that the filter chain will be invoked
        MockFilterChain chain = new MockFilterChain(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
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
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);

        assertTrue(request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY) == null);
        assertEquals(401, response.getError());
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

        // Launch an application context and access our bean
        ApplicationContext ctx = new ClassPathXmlApplicationContext(
                "net/sf/acegisecurity/ui/basicauth/filtertest-valid.xml");
        BasicProcessingFilter filter = (BasicProcessingFilter) ctx.getBean(
                "basicProcessingFilter");

        // Setup our filter configuration
        MockFilterConfig config = new MockFilterConfig();

        // Setup our expectation that the filter chain will not be invoked, as we get a 403 forbidden response
        MockFilterChain chain = new MockFilterChain(false);
        MockHttpServletResponse response = new MockHttpServletResponse();

        // Test
        executeFilterInContainerSimulator(config, filter, request, response,
            chain);

        assertTrue(request.getSession().getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY) == null);
        assertEquals(401, response.getError());
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
