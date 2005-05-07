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

package net.sf.acegisecurity.context;

import junit.framework.TestCase;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.MockFilterConfig;
import net.sf.acegisecurity.adapters.PrincipalAcegiUserToken;
import net.sf.acegisecurity.context.HttpSessionContextIntegrationFilter;

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
public class HttpSessionContextIntegrationFilterTests extends TestCase {
    //~ Constructors ===========================================================

    public HttpSessionContextIntegrationFilterTests() {
        super();
    }

    public HttpSessionContextIntegrationFilterTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(HttpSessionContextIntegrationFilterTests.class);
    }

    public void testExistingContextContentsCopiedIntoContextHolderFromSessionAndChangesToContextCopiedBackToSession()
        throws Exception {
        // Build an Authentication object we simulate came from HttpSession
        PrincipalAcegiUserToken sessionPrincipal = new PrincipalAcegiUserToken("key",
                "someone", "password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("SOME_ROLE")});

        // Build an Authentication object we simulate our Authentication changed it to
        PrincipalAcegiUserToken updatedPrincipal = new PrincipalAcegiUserToken("key",
                "someone", "password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("SOME_DIFFERENT_ROLE")});

        // Build a mock request
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession().setAttribute(HttpSessionContextIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_CONTEXT_KEY,
            sessionPrincipal);

        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = new MockFilterChain(sessionPrincipal,
                updatedPrincipal);

        // Prepare filter
        HttpSessionContextIntegrationFilter filter = new HttpSessionContextIntegrationFilter();

        // Execute filter
        executeFilterInContainerSimulator(new MockFilterConfig(), filter,
            request, response, chain);

        // Obtain new/update Authentication from HttpSession
        Authentication auth = (Authentication) request.getSession()
                                                      .getAttribute(HttpSessionContextIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_CONTEXT_KEY);
        assertEquals(updatedPrincipal, auth);
    }

    public void testHttpSessionCreatedWhenContextHolderChanges()
        throws Exception {
        // Build an Authentication object we simulate our Authentication changed it to
        PrincipalAcegiUserToken updatedPrincipal = new PrincipalAcegiUserToken("key",
                "someone", "password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("SOME_DIFFERENT_ROLE")});

        // Build a mock request
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = new MockFilterChain(null, updatedPrincipal);

        // Prepare filter
        HttpSessionContextIntegrationFilter filter = new HttpSessionContextIntegrationFilter();

        // Execute filter
        executeFilterInContainerSimulator(new MockFilterConfig(), filter,
            request, response, chain);

        // Obtain new/update Authentication from HttpSession
        Authentication auth = (Authentication) request.getSession(false)
                                                      .getAttribute(HttpSessionContextIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_CONTEXT_KEY);
        assertEquals(updatedPrincipal, auth);
    }

    public void testHttpSessionNotCreatedUnlessContextHolderChanges()
        throws Exception {
        // Build a mock request
        MockHttpServletRequest request = new MockHttpServletRequest(null, null);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = new MockFilterChain(null, null);

        // Prepare filter
        HttpSessionContextIntegrationFilter filter = new HttpSessionContextIntegrationFilter();

        // Execute filter
        executeFilterInContainerSimulator(new MockFilterConfig(), filter,
            request, response, chain);

        // Obtain new/update Authentication from HttpSession
        assertNull(request.getSession(false));
    }

    public void testHttpSessionWithNonContextInWellKnownLocationIsOverwritten()
        throws Exception {
        // Build an Authentication object we simulate our Authentication changed it to
        PrincipalAcegiUserToken updatedPrincipal = new PrincipalAcegiUserToken("key",
                "someone", "password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("SOME_DIFFERENT_ROLE")});

        // Build a mock request
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession().setAttribute(HttpSessionContextIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_CONTEXT_KEY,
            "NOT_A_CONTEXT_OBJECT");

        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = new MockFilterChain(null, updatedPrincipal);

        // Prepare filter
        HttpSessionContextIntegrationFilter filter = new HttpSessionContextIntegrationFilter();

        // Execute filter
        executeFilterInContainerSimulator(new MockFilterConfig(), filter,
            request, response, chain);

        // Obtain new/update Authentication from HttpSession
        Authentication auth = (Authentication) request.getSession()
                                                      .getAttribute(HttpSessionContextIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_CONTEXT_KEY);
        assertEquals(updatedPrincipal, auth);
    }

    private void executeFilterInContainerSimulator(FilterConfig filterConfig,
        Filter filter, ServletRequest request, ServletResponse response,
        FilterChain filterChain) throws ServletException, IOException {
        filter.init(filterConfig);
        filter.doFilter(request, response, filterChain);
        filter.destroy();
    }

    //~ Inner Classes ==========================================================

    private class MockFilterChain extends TestCase implements FilterChain {
        private Authentication changeContextHolder;
        private Authentication expectedOnContextHolder;

        public MockFilterChain(Authentication expectedOnContextHolder,
            Authentication changeContextHolder) {
            this.expectedOnContextHolder = expectedOnContextHolder;
            this.changeContextHolder = changeContextHolder;
        }

        private MockFilterChain() {}

        public void doFilter(ServletRequest arg0, ServletResponse arg1)
            throws IOException, ServletException {
            if (expectedOnContextHolder != null) {
                assertEquals(expectedOnContextHolder,
                    SecurityContext.getAuthentication());
            }

            if (changeContextHolder != null) {
                SecurityContext.setAuthentication(changeContextHolder);
            }
        }
    }
}
