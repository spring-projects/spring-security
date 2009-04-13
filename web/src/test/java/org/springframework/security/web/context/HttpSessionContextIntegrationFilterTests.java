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

package org.springframework.security.web.context;

import junit.framework.TestCase;

import org.springframework.security.MockFilterConfig;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.context.HttpSessionContextIntegrationFilter;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * Tests {@link HttpSessionContextIntegrationFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
@SuppressWarnings("deprecation")
public class HttpSessionContextIntegrationFilterTests extends TestCase {
    // Build an Authentication object we simulate came from HttpSession
    private UsernamePasswordAuthenticationToken sessionPrincipal = new UsernamePasswordAuthenticationToken(
            "someone",
            "password",
            AuthorityUtils.createAuthorityList("SOME_ROLE"));


    //~ Methods ========================================================================================================

    private static void executeFilterInContainerSimulator(
            FilterConfig filterConfig, Filter filter, ServletRequest request,
            ServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        filter.init(filterConfig);
        filter.doFilter(request, response, filterChain);
        filter.destroy();
    }

    public void testDetectsIncompatibleSessionProperties() throws Exception {
        HttpSessionContextIntegrationFilter filter = new HttpSessionContextIntegrationFilter();

        try {
            filter.setAllowSessionCreation(false);
            filter.setForceEagerSessionCreation(true);
            filter.afterPropertiesSet();
            fail("Shown have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        filter.setAllowSessionCreation(true);
        filter.afterPropertiesSet();
        assertTrue(true);
    }

    public void testDetectsMissingOrInvalidContext() throws Exception {
        HttpSessionContextIntegrationFilter filter = new HttpSessionContextIntegrationFilter();

        try {
            filter.setContextClass(null);
            filter.afterPropertiesSet();
            fail("Shown have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            filter.setContextClass(Integer.class);
            assertEquals(Integer.class, filter.getContextClass());
            filter.afterPropertiesSet();
            fail("Shown have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testExceptionWithinFilterChainStillClearsSecurityContextHolder() throws Exception {

        // Build a Context to store in HttpSession (simulating prior request)
        SecurityContext sc = new SecurityContextImpl();
        sc.setAuthentication(sessionPrincipal);

        // Build a mock request
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession().setAttribute(
                HttpSessionContextIntegrationFilter.SPRING_SECURITY_CONTEXT_KEY,
                sc);

        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = new MockFilterChain(sessionPrincipal, null,
                new IOException());

        // Prepare filter
        HttpSessionContextIntegrationFilter filter = new HttpSessionContextIntegrationFilter();
        filter.setContextClass(SecurityContextImpl.class);
        filter.afterPropertiesSet();

        // Execute filter
        try {
            executeFilterInContainerSimulator(new MockFilterConfig(), filter,
                    request, response, chain);
            fail("We should have received the IOException thrown inside the filter chain here");
        } catch (IOException ioe) {
            assertTrue(true);
        }

        // Check the SecurityContextHolder is null, even though an exception was
        // thrown during chain
        assertEquals(new SecurityContextImpl(), SecurityContextHolder.getContext());
        assertNull("Should have cleared FILTER_APPLIED",
                request.getAttribute(HttpSessionContextIntegrationFilter.FILTER_APPLIED));
    }

    public void testExistingContextContentsCopiedIntoContextHolderFromSessionAndChangesToContextCopiedBackToSession()
            throws Exception {

        // Build an Authentication object we simulate came from HttpSession
        UsernamePasswordAuthenticationToken updatedPrincipal = new UsernamePasswordAuthenticationToken(
                "someone",
                "password",
                AuthorityUtils.createAuthorityList("SOME_DIFFERENT_ROLE"));

        // Build a Context to store in HttpSession (simulating prior request)
        SecurityContext sc = new SecurityContextImpl();
        sc.setAuthentication(sessionPrincipal);

        // Build a mock request
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession().setAttribute(
                HttpSessionContextIntegrationFilter.SPRING_SECURITY_CONTEXT_KEY,
                sc);

        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = new MockFilterChain(sessionPrincipal,
                updatedPrincipal, null);

        // Prepare filter
        HttpSessionContextIntegrationFilter filter = new HttpSessionContextIntegrationFilter();
        filter.setContextClass(SecurityContextImpl.class);
        filter.afterPropertiesSet();

        // Execute filter
        executeFilterInContainerSimulator(new MockFilterConfig(), filter,
                request, response, chain);

        // Obtain new/update Authentication from HttpSession
        SecurityContext context = (SecurityContext) request.getSession().getAttribute(
                        HttpSessionContextIntegrationFilter.SPRING_SECURITY_CONTEXT_KEY);
        assertEquals(updatedPrincipal, ((SecurityContext) context).getAuthentication());
    }

    public void testHttpSessionCreatedWhenContextHolderChanges() throws Exception {
        // Build an Authentication object we simulate our Authentication changed it to
        UsernamePasswordAuthenticationToken updatedPrincipal = new UsernamePasswordAuthenticationToken(
                "someone",
                "password",
                AuthorityUtils.createAuthorityList("SOME_ROLE"));

        // Build a mock request
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = new MockFilterChain(null, updatedPrincipal, null);

        // Prepare filter
        HttpSessionContextIntegrationFilter filter = new HttpSessionContextIntegrationFilter();
        filter.setContextClass(SecurityContextImpl.class);
        // don't call afterPropertiesSet to test case when Spring filter.afterPropertiesSet(); isn't called

        // Execute filter
        executeFilterInContainerSimulator(new MockFilterConfig(), filter, request, response, chain);

        // Obtain new/updated Authentication from HttpSession
        SecurityContext context = (SecurityContext) request.getSession(false).getAttribute(
                        HttpSessionContextIntegrationFilter.SPRING_SECURITY_CONTEXT_KEY);
        assertEquals(updatedPrincipal, ((SecurityContext) context).getAuthentication());
    }

    public void testHttpSessionEagerlyCreatedWhenDirected() throws Exception {
        // Build a mock request
        MockHttpServletRequest request = new MockHttpServletRequest(null, null);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = new MockFilterChain(null, null, null);

        // Prepare filter
        HttpSessionContextIntegrationFilter filter = new HttpSessionContextIntegrationFilter();
        filter.setContextClass(SecurityContextImpl.class);
        filter.setForceEagerSessionCreation(true); // non-default
        filter.afterPropertiesSet();

        // Execute filter
        executeFilterInContainerSimulator(new MockFilterConfig(), filter,
                request, response, chain);

        // Check the session is not null
        assertNotNull(request.getSession(false));
    }

    public void testHttpSessionNotCreatedUnlessContextHolderChanges() throws Exception {
        // Build a mock request
        MockHttpServletRequest request = new MockHttpServletRequest(null, null);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = new MockFilterChain(null, null, null);

        // Prepare filter
        HttpSessionContextIntegrationFilter filter = new HttpSessionContextIntegrationFilter();
        filter.setContextClass(SecurityContextImpl.class);
        filter.afterPropertiesSet();

        // Execute filter
        executeFilterInContainerSimulator(new MockFilterConfig(), filter,
                request, response, chain);

        // Check the session is null
        assertNull(request.getSession(false));
    }

    public void testHttpSessionWithNonContextInWellKnownLocationIsOverwritten() throws Exception {
        // Build an Authentication object we simulate our Authentication changed it to
        UsernamePasswordAuthenticationToken updatedPrincipal = new UsernamePasswordAuthenticationToken(
                "someone",
                "password",
                AuthorityUtils.createAuthorityList("SOME_DIFFERENT_ROLE"));

        // Build a mock request
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession().setAttribute(
                HttpSessionContextIntegrationFilter.SPRING_SECURITY_CONTEXT_KEY,
                "NOT_A_CONTEXT_OBJECT");

        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = new MockFilterChain(null, updatedPrincipal, null);

        // Prepare filter
        HttpSessionContextIntegrationFilter filter = new HttpSessionContextIntegrationFilter();
        filter.setContextClass(SecurityContextImpl.class);
        filter.afterPropertiesSet();

        // Execute filter
        executeFilterInContainerSimulator(new MockFilterConfig(), filter, request, response, chain);

        // Obtain new/update Authentication from HttpSession
        SecurityContext context = (SecurityContext) request.getSession().getAttribute(
                        HttpSessionContextIntegrationFilter.SPRING_SECURITY_CONTEXT_KEY);
        assertEquals(updatedPrincipal, ((SecurityContext) context).getAuthentication());
    }

    //~ Inner Classes ==================================================================================================

    private class MockFilterChain extends TestCase implements FilterChain {
        private Authentication changeContextHolder;
        private Authentication expectedOnContextHolder;
        private IOException toThrowDuringChain;

        public MockFilterChain(Authentication expectedOnContextHolder,
                Authentication changeContextHolder,
                IOException toThrowDuringChain) {
            this.expectedOnContextHolder = expectedOnContextHolder;
            this.changeContextHolder = changeContextHolder;
            this.toThrowDuringChain = toThrowDuringChain;
        }

        public void doFilter(ServletRequest arg0, ServletResponse arg1) throws IOException, ServletException {
            if (expectedOnContextHolder != null) {
                assertEquals(expectedOnContextHolder, SecurityContextHolder.getContext().getAuthentication());
            }

            if (changeContextHolder != null) {
                SecurityContext sc = SecurityContextHolder.getContext();
                sc.setAuthentication(changeContextHolder);
                SecurityContextHolder.setContext(sc);
            }

            if (toThrowDuringChain != null) {
                throw toThrowDuringChain;
            }

        }
    }
}
