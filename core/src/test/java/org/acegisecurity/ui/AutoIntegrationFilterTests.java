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

import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.MockHttpServletRequest;
import net.sf.acegisecurity.adapters.MockPrincipal;
import net.sf.acegisecurity.adapters.PrincipalAcegiUserToken;
import net.sf.acegisecurity.adapters.jboss.JbossIntegrationFilter;
import net.sf.acegisecurity.adapters.jboss.MockInitialContext;
import net.sf.acegisecurity.adapters.jboss.MockJbossIntegrationFilter;
import net.sf.acegisecurity.ui.webapp.HttpSessionIntegrationFilter;

import org.jboss.security.SimplePrincipal;

import java.security.Principal;

import java.util.HashSet;
import java.util.Set;

import javax.naming.Context;

import javax.security.auth.Subject;

import javax.servlet.ServletRequest;


/**
 * Tests {@link AutoIntegrationFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AutoIntegrationFilterTests extends TestCase {
    //~ Constructors ===========================================================

    public AutoIntegrationFilterTests() {
        super();
    }

    public AutoIntegrationFilterTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(AutoIntegrationFilterTests.class);
    }

    public void testDetectsAuthenticationObjectInHttpRequest() {
        AutoIntegrationFilter filter = new AutoIntegrationFilter();
        PrincipalAcegiUserToken principal = new PrincipalAcegiUserToken("key",
                "someone", "password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("SOME_ROLE")});
        Object result = filter.extractFromContainer(new MockHttpServletRequest(
                    principal, null));

        if (!(result instanceof PrincipalAcegiUserToken)) {
            fail("Should have returned PrincipalAcegiUserToken");
        }

        PrincipalAcegiUserToken castResult = (PrincipalAcegiUserToken) result;
        assertEquals(principal, result);
    }

    public void testDetectsAuthenticationObjectInHttpSession() {
        PrincipalAcegiUserToken principal = new PrincipalAcegiUserToken("key",
                "someone", "password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("SOME_ROLE")});

        AutoIntegrationFilter filter = new MockAutoIntegrationFilterHttpSession(new MockHttpSessionIntegrationFilter(
                    principal));
        Object result = filter.extractFromContainer(new MockHttpServletRequest(
                    null, null));

        if (!(result instanceof PrincipalAcegiUserToken)) {
            fail("Should have returned PrincipalAcegiUserToken");
        }

        PrincipalAcegiUserToken castResult = (PrincipalAcegiUserToken) result;
        assertEquals(principal, result);
    }

    public void testDetectsAuthenticationObjectInJboss() {
        // Prepare a mock Jboss environment reflecting completed authentication
        PrincipalAcegiUserToken principal = new PrincipalAcegiUserToken("key",
                "someone", "password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("SOME_ROLE")});
        Context context = new MockInitialContext(makeIntoSubject(principal));
        JbossIntegrationFilter jbossFilter = new MockJbossIntegrationFilter(context);

        // Create a SimplePrincipal, which is what JBoss places into HttpRequest
        SimplePrincipal simplePrincipal = new SimplePrincipal("TEST");

        // Now try to extract authentication information via our mock AutoIntegrationFilter
        AutoIntegrationFilter filter = new MockAutoIntegrationFilterJboss(jbossFilter);
        Object result = filter.extractFromContainer(new MockHttpServletRequest(
                    simplePrincipal, null));

        System.out.println(result);

        if (!(result instanceof PrincipalAcegiUserToken)) {
            fail("Should have returned PrincipalAcegiUserToken");
        }

        PrincipalAcegiUserToken castResult = (PrincipalAcegiUserToken) result;
        assertEquals(principal, result);
    }

    public void testHandlesIfHttpRequestIsNullForSomeReason() {
        AutoIntegrationFilter filter = new AutoIntegrationFilter();
        assertEquals(null, filter.extractFromContainer(null));
    }

    public void testHandlesIfThereIsNoPrincipal() {
        AutoIntegrationFilter filter = new AutoIntegrationFilter();
        assertEquals(null,
            filter.extractFromContainer(new MockHttpServletRequest(null, null)));
    }

    public void testReturnsNullIfNonAuthenticationObjectInHttpRequest() {
        AutoIntegrationFilter filter = new AutoIntegrationFilter();
        assertEquals(null,
            filter.extractFromContainer(
                new MockHttpServletRequest(new MockPrincipal(), null)));
    }

    private Subject makeIntoSubject(Principal principal) {
        Set principals = new HashSet();
        principals.add(principal);

        return new Subject(false, principals, new HashSet(), new HashSet());
    }

    //~ Inner Classes ==========================================================

    private class MockAutoIntegrationFilterHttpSession
        extends AutoIntegrationFilter {
        private HttpSessionIntegrationFilter filter;

        public MockAutoIntegrationFilterHttpSession(
            HttpSessionIntegrationFilter filter) {
            this.filter = filter;
        }

        private MockAutoIntegrationFilterHttpSession() {
            super();
        }

        protected HttpSessionIntegrationFilter getHttpSessionIntegrationFilter() {
            return this.filter;
        }
    }

    private class MockAutoIntegrationFilterJboss extends AutoIntegrationFilter {
        private JbossIntegrationFilter filter;

        public MockAutoIntegrationFilterJboss(JbossIntegrationFilter filter) {
            this.filter = filter;
        }

        private MockAutoIntegrationFilterJboss() {
            super();
        }

        protected JbossIntegrationFilter getJbossIntegrationFilter() {
            return this.filter;
        }
    }

    private class MockHttpSessionIntegrationFilter
        extends HttpSessionIntegrationFilter {
        private Object toReturn;

        public MockHttpSessionIntegrationFilter(Object toReturn) {
            this.toReturn = toReturn;
        }

        private MockHttpSessionIntegrationFilter() {
            super();
        }

        public Object extractFromContainer(ServletRequest request) {
            return this.toReturn;
        }
    }
}
