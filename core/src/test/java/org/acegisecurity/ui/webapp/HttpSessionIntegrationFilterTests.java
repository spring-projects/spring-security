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

import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.MockHttpServletRequest;
import net.sf.acegisecurity.MockHttpSession;
import net.sf.acegisecurity.adapters.PrincipalAcegiUserToken;

import java.util.List;
import java.util.Vector;


/**
 * Tests {@link HttpSessionIntegrationFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class HttpSessionIntegrationFilterTests extends TestCase {
    //~ Constructors ===========================================================

    public HttpSessionIntegrationFilterTests() {
        super();
    }

    public HttpSessionIntegrationFilterTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(HttpSessionIntegrationFilterTests.class);
    }

    public void testCommitFailSilentlyIfNullsProvided() {
        HttpSessionIntegrationFilter filter = new HttpSessionIntegrationFilter();
        filter.commitToContainer(null, null);
        assertTrue(true);
    }

    public void testCommitOperation() {
        // Build an Authentication object we want returned
        PrincipalAcegiUserToken principal = new PrincipalAcegiUserToken("key",
                "someone", "password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("SOME_ROLE")});

        // Build a mock request
        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequest request = new MockHttpServletRequest(null,
                session);

        // Try to commit
        HttpSessionIntegrationFilter filter = new HttpSessionIntegrationFilter();
        filter.commitToContainer(request, principal);

        // Check it committed the object
        Object result = session.getAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY);
        assertEquals(principal, result);
    }

    public void testCommitOperationGracefullyIgnoredIfSessionIsNull() {
        PrincipalAcegiUserToken principal = new PrincipalAcegiUserToken("key",
                "someone", "password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("SOME_ROLE")});

        // Build a mock request
        MockHttpSession session = null;
        MockHttpServletRequest request = new MockHttpServletRequest(null,
                session);

        HttpSessionIntegrationFilter filter = new HttpSessionIntegrationFilter();
        filter.commitToContainer(request, principal);

        assertTrue(true);
    }

    public void testCorrectOperation() {
        // Build a mock session containing the authenticated user
        PrincipalAcegiUserToken principal = new PrincipalAcegiUserToken("key",
                "someone", "password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("SOME_ROLE")});
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY,
            principal);

        // Confirm filter can extract required credentials from session
        HttpSessionIntegrationFilter filter = new HttpSessionIntegrationFilter();
        Object result = filter.extractFromContainer(new MockHttpServletRequest(
                    null, session));

        if (!(result instanceof PrincipalAcegiUserToken)) {
            fail("Should have returned PrincipalAcegiUserToken");
        }

        PrincipalAcegiUserToken castResult = (PrincipalAcegiUserToken) result;
        assertEquals(principal, result);
    }

    public void testDetectsInvalidAdditionalAttributes() {
        HttpSessionIntegrationFilter filter = new HttpSessionIntegrationFilter();
        List list = new Vector();
        list.add(new Integer(4));

        try {
            filter.setAdditionalAttributes(list);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testHandlesIfHttpRequestIsNullForSomeReason() {
        HttpSessionIntegrationFilter filter = new HttpSessionIntegrationFilter();
        assertEquals(null, filter.extractFromContainer(null));
    }

    public void testHandlesIfHttpSessionIsNullForSomeReason() {
        HttpSessionIntegrationFilter filter = new HttpSessionIntegrationFilter();
        assertEquals(null,
            filter.extractFromContainer(new MockHttpServletRequest(null, null)));
    }

    public void testHandlesIfThereIsNoPrincipalInTheHttpSession() {
        HttpSessionIntegrationFilter filter = new HttpSessionIntegrationFilter();
        assertEquals(null,
            filter.extractFromContainer(
                new MockHttpServletRequest(null, new MockHttpSession())));
    }

    public void testSettingEmptyListForAdditionalAttributesIsAcceptable() {
        HttpSessionIntegrationFilter filter = new HttpSessionIntegrationFilter();
        filter.setAdditionalAttributes(new Vector());
        assertTrue(filter.getAdditionalAttributes() != null);
    }

    public void testSettingNullForAdditionalAttributesIsAcceptable() {
        HttpSessionIntegrationFilter filter = new HttpSessionIntegrationFilter();
        filter.setAdditionalAttributes(null);
        assertNull(filter.getAdditionalAttributes());
    }

    public void testUpdatesAdditionalAttributes() {
        // Build a mock session containing the authenticated user
        PrincipalAcegiUserToken principal = new PrincipalAcegiUserToken("key",
                "someone", "password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("SOME_ROLE")});
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(HttpSessionIntegrationFilter.ACEGI_SECURITY_AUTHENTICATION_KEY,
            principal);

        // Check our attributes are not presently set
        assertNull(session.getAttribute("SOME_EXTRA_ATTRIBUTE_1"));
        assertNull(session.getAttribute("SOME_EXTRA_ATTRIBUTE_2"));

        // Generate filter
        HttpSessionIntegrationFilter filter = new HttpSessionIntegrationFilter();
        List list = new Vector();
        list.add("SOME_EXTRA_ATTRIBUTE_1");
        list.add("SOME_EXTRA_ATTRIBUTE_2");
        filter.setAdditionalAttributes(list);

        // Confirm filter can extract required credentials from session
        Object result = filter.extractFromContainer(new MockHttpServletRequest(
                    null, session));

        if (!(result instanceof PrincipalAcegiUserToken)) {
            fail("Should have returned PrincipalAcegiUserToken");
        }

        PrincipalAcegiUserToken castResult = (PrincipalAcegiUserToken) result;
        assertEquals(principal, result);

        // Now double-check it updated our earlier set additionalAttributes
        assertEquals(principal, session.getAttribute("SOME_EXTRA_ATTRIBUTE_1"));
        assertEquals(principal, session.getAttribute("SOME_EXTRA_ATTRIBUTE_2"));
    }
}
