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

package org.acegisecurity.ui.basicauth;

import org.acegisecurity.MockAuthenticationEntryPoint;
import org.acegisecurity.MockAuthenticationManager;
import org.acegisecurity.MockFilterConfig;
import org.acegisecurity.MockFilterChain;
import org.acegisecurity.providers.dao.DaoAuthenticationProvider;
import org.acegisecurity.providers.ProviderManager;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.context.SecurityContextImpl;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.memory.InMemoryDaoImpl;
import org.acegisecurity.userdetails.memory.UserMapEditor;
import org.acegisecurity.userdetails.memory.UserMap;

import org.apache.commons.codec.binary.Base64;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEvent;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

import org.jmock.MockObjectTestCase;
import org.jmock.Mock;

import java.io.IOException;
import java.util.Arrays;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;


/**
 * Tests {@link BasicProcessingFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class BasicProcessingFilterTests extends MockObjectTestCase {
    private BasicProcessingFilter filter;
    //~ Constructors ===========================================================

    public BasicProcessingFilterTests() {
        super();
    }

    public BasicProcessingFilterTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(BasicProcessingFilterTests.class);
    }

    protected void setUp() throws Exception {
        super.setUp();
        SecurityContextHolder.setContext(new SecurityContextImpl());

        // Create User Details Service, provider and authentication manager
        InMemoryDaoImpl dao = new InMemoryDaoImpl();
        UserMapEditor editor = new UserMapEditor();
        editor.setAsText("marissa=koala,ROLE_ONE,ROLE_TWO,enabled\r\n");
        dao.setUserMap((UserMap)editor.getValue());

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(dao);

        ProviderManager manager = new ProviderManager();
        manager.setProviders(Arrays.asList(new Object[] {provider}));
        manager.setApplicationEventPublisher(new MockApplicationEventPublisher());
        manager.afterPropertiesSet();

        filter = new BasicProcessingFilter();
        filter.setAuthenticationManager(manager);
        filter.setAuthenticationEntryPoint(new BasicProcessingFilterEntryPoint());
    }

    protected void tearDown() throws Exception {
        super.tearDown();
        SecurityContextHolder.setContext(new SecurityContextImpl());
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
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath("/some_file.html");

        // Test
        executeFilterInContainerSimulator(filter, request, true);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
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
        String token = "NOT_A_VALID_TOKEN_AS_MISSING_COLON";
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization",
            "Basic " + new String(Base64.encodeBase64(token.getBytes())));
        request.setServletPath("/some_file.html");
        request.setSession(new MockHttpSession());

        // The filter chain shouldn't proceed
        executeFilterInContainerSimulator(filter, request, false);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    public void testNormalOperation() throws Exception {
        // Setup our HTTP request
        String token = "marissa:koala";
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization",
            "Basic " + new String(Base64.encodeBase64(token.getBytes())));
        request.setServletPath("/some_file.html");
        request.setSession(new MockHttpSession());

        // Test
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        executeFilterInContainerSimulator(filter, request, true);

        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals("marissa",
            ((UserDetails) SecurityContextHolder.getContext().getAuthentication()
                                                .getPrincipal()).getUsername());
    }

    public void testOtherAuthorizationSchemeIsIgnored()
        throws Exception {
        // Setup our HTTP request
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "SOME_OTHER_AUTHENTICATION_SCHEME");
        request.setServletPath("/some_file.html");

        // Test
        executeFilterInContainerSimulator(filter, request, true);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
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
            filter.setAuthenticationEntryPoint(
                    new MockAuthenticationEntryPoint("x"));
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
        String token = "marissa:koala";
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization",
            "Basic " + new String(Base64.encodeBase64(token.getBytes())));
        request.setServletPath("/some_file.html");
        request.setSession(new MockHttpSession());

        // Test
        executeFilterInContainerSimulator(filter, request, true);

        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals("marissa",
            ((UserDetails) SecurityContextHolder.getContext().getAuthentication()
                                                .getPrincipal()).getUsername());

        // NOW PERFORM FAILED AUTHENTICATION
        // Setup our HTTP request
        token = "otherUser:WRONG_PASSWORD";
        request = new MockHttpServletRequest();
        request.addHeader("Authorization",
            "Basic " + new String(Base64.encodeBase64(token.getBytes())));
        request.setServletPath("/some_file.html");
        request.setSession(new MockHttpSession());

        // Test - the filter chain will not be invoked, as we get a 403 forbidden response
        MockHttpServletResponse response =
            executeFilterInContainerSimulator(filter, request, false);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals(401, response.getStatus());
    }

    public void testWrongPasswordReturnsForbidden() throws Exception {
        // Setup our HTTP request
        String token = "marissa:WRONG_PASSWORD";
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization",
            "Basic " + new String(Base64.encodeBase64(token.getBytes())));
        request.setServletPath("/some_file.html");
        request.setSession(new MockHttpSession());

        // Test - the filter chain will not be invoked, as we get a 403 forbidden response
        MockHttpServletResponse response =
            executeFilterInContainerSimulator(filter, request, false);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertEquals(401, response.getStatus());
    }

    private MockHttpServletResponse executeFilterInContainerSimulator(Filter filter,
            ServletRequest request, boolean expectChainToProceed)
            throws ServletException, IOException {
        filter.init(new MockFilterConfig());
        MockHttpServletResponse response = new MockHttpServletResponse();
        Mock mockChain = mock(FilterChain.class);
        FilterChain chain = (FilterChain)mockChain.proxy();

        mockChain.expects( expectChainToProceed ? once() : never() ).method("doFilter");

        filter.doFilter(request, response, chain);
        filter.destroy();

        return response;
    }

    private class MockApplicationEventPublisher implements ApplicationEventPublisher {

		public MockApplicationEventPublisher() {
		}

    	public void publishEvent(ApplicationEvent event) {
		}
    }
}
