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

package net.sf.acegisecurity.adapters.jboss;

import junit.framework.TestCase;

import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.adapters.MockPrincipal;
import net.sf.acegisecurity.adapters.PrincipalAcegiUserToken;

import org.springframework.mock.web.MockHttpServletRequest;

import java.security.Principal;

import java.util.HashSet;
import java.util.Set;

import javax.naming.Context;

import javax.security.auth.Subject;


/**
 * Tests {@link JbossIntegrationFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class JbossIntegrationFilterTests extends TestCase {
    //~ Constructors ===========================================================

    public JbossIntegrationFilterTests() {
        super();
    }

    public JbossIntegrationFilterTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(JbossIntegrationFilterTests.class);
    }

    public void testCorrectOperation() {
        PrincipalAcegiUserToken principal = new PrincipalAcegiUserToken("key",
                "someone", "password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("SOME_ROLE")});

        JbossIntegrationFilter filter = new MockJbossIntegrationFilter(new MockInitialContext(
                    makeIntoSubject(principal)));

        Object result = filter.extractFromContainer(new MockHttpServletRequest());

        if (!(result instanceof PrincipalAcegiUserToken)) {
            fail("Should have returned PrincipalAcegiUserToken");
        }

        PrincipalAcegiUserToken castResult = (PrincipalAcegiUserToken) result;
        assertEquals(principal, result);

        MockHttpServletRequest mockRequest = new MockHttpServletRequest();
        mockRequest.setUserPrincipal(principal);

        filter.commitToContainer(mockRequest, principal);
    }

    public void testReturnsNullIfContextReturnsSomethingOtherThanASubject() {
        JbossIntegrationFilter filter = new MockJbossIntegrationFilter(new MockInitialContext(
                    "THIS_IS_NOT_A_SUBJECT"));
        assertEquals(null,
            filter.extractFromContainer(new MockHttpServletRequest(null, null)));
    }

    public void testReturnsNullIfInitialContextHasNullPrincipal() {
        JbossIntegrationFilter filter = new MockJbossIntegrationFilter(new MockInitialContext(
                    makeIntoSubject(null)));
        assertEquals(null,
            filter.extractFromContainer(new MockHttpServletRequest(null, null)));
    }

    public void testReturnsNullIfInitialContextHasNullSubject() {
        JbossIntegrationFilter filter = new MockJbossIntegrationFilter(new MockInitialContext(
                    null));
        assertEquals(null,
            filter.extractFromContainer(new MockHttpServletRequest(null, null)));
    }

    public void testReturnsNullIfInitialContextIsNull() {
        JbossIntegrationFilter filter = new MockJbossIntegrationFilter(null);

        Object result = filter.extractFromContainer(new MockHttpServletRequest(
                    null, null));
        assertEquals(null, filter.extractFromContainer(null));
    }

    public void testReturnsNullIfPrincipalNotAnAuthenticationImplementation() {
        JbossIntegrationFilter filter = new MockJbossIntegrationFilter(new MockInitialContext(
                    makeIntoSubject(new MockPrincipal())));
        assertEquals(null,
            filter.extractFromContainer(new MockHttpServletRequest(null, null)));
    }

    public void testTestingObjectReturnsInitialContext()
        throws Exception {
        JbossIntegrationFilter filter = new JbossIntegrationFilter();
        assertTrue(filter.getLookupContext() instanceof Context);
    }

    private Subject makeIntoSubject(Principal principal) {
        Set principals = new HashSet();
        principals.add(principal);

        return new Subject(false, principals, new HashSet(), new HashSet());
    }
}
