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

package org.springframework.security.adapters.jboss;

import junit.framework.TestCase;

import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;

import org.springframework.security.adapters.PrincipalAcegiUserToken;

import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.context.SecurityContextImpl;

import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import java.security.Principal;

import java.util.HashSet;
import java.util.Set;

import javax.naming.Context;

import javax.security.auth.Subject;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


/**
 * Tests {@link JbossIntegrationFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class JbossIntegrationFilterTests extends TestCase {
    //~ Constructors ===================================================================================================

    public JbossIntegrationFilterTests() {
        super();
    }

    public JbossIntegrationFilterTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    private void executeFilterInContainerSimulator(FilterConfig filterConfig, Filter filter, ServletRequest request,
        ServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {
        filter.init(filterConfig);
        filter.doFilter(request, response, filterChain);
        filter.destroy();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(JbossIntegrationFilterTests.class);
    }

    private Subject makeIntoSubject(Principal principal) {
        Set principals = new HashSet();
        principals.add(principal);

        return new Subject(false, principals, new HashSet(), new HashSet());
    }

    protected void setUp() throws Exception {
        super.setUp();
        SecurityContextHolder.setContext(new SecurityContextImpl());
    }

    protected void tearDown() throws Exception {
        super.tearDown();
        SecurityContextHolder.setContext(new SecurityContextImpl());
    }

    public void testCorrectOperation() throws Exception {
        PrincipalAcegiUserToken principal = new PrincipalAcegiUserToken("key", "someone", "password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("SOME_ROLE")}, null);

        JbossIntegrationFilter filter = new MockJbossIntegrationFilter(new MockInitialContext(makeIntoSubject(principal)));

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, null, chain);

        assertEquals(principal, SecurityContextHolder.getContext().getAuthentication());
        SecurityContextHolder.setContext(new SecurityContextImpl());
    }

    public void testReturnsNullIfContextReturnsSomethingOtherThanASubject()
        throws Exception {
        JbossIntegrationFilter filter = new MockJbossIntegrationFilter(new MockInitialContext("THIS_IS_NOT_A_SUBJECT"));

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, null, chain);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    public void testReturnsNullIfInitialContextHasNullPrincipal()
        throws Exception {
        JbossIntegrationFilter filter = new MockJbossIntegrationFilter(new MockInitialContext(makeIntoSubject(null)));

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, null, chain);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    public void testReturnsNullIfInitialContextHasNullSubject()
        throws Exception {
        JbossIntegrationFilter filter = new MockJbossIntegrationFilter(new MockInitialContext(null));

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, null, chain);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    public void testReturnsNullIfInitialContextIsNull()
        throws Exception {
        JbossIntegrationFilter filter = new MockJbossIntegrationFilter(null);

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, null, chain);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    public void testReturnsNullIfPrincipalNotAnAuthenticationImplementation()
        throws Exception {
        JbossIntegrationFilter filter = new MockJbossIntegrationFilter(new MockInitialContext(makeIntoSubject(
                        new Principal() {
                    public String getName() {
                        return "MockPrincipal";
                    }
                })));

        MockHttpServletRequest request = new MockHttpServletRequest();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, null, chain);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    public void testTestingObjectReturnsInitialContext()
        throws Exception {
        JbossIntegrationFilter filter = new JbossIntegrationFilter();
        assertTrue(filter.getLookupContext() instanceof Context);
    }

    //~ Inner Classes ==================================================================================================

    private class MockFilterChain implements FilterChain {
        public void doFilter(ServletRequest arg0, ServletResponse arg1)
            throws IOException, ServletException {}
    }
}
