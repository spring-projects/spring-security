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

package net.sf.acegisecurity.adapters;

import junit.framework.TestCase;

import net.sf.acegisecurity.*;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;


/**
 * Tests {@link HttpRequestIntegrationFilter}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class HttpRequestIntegrationFilterTests extends TestCase {
    //~ Constructors ===========================================================

    public HttpRequestIntegrationFilterTests() {
        super();
    }

    public HttpRequestIntegrationFilterTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(HttpRequestIntegrationFilterTests.class);
    }

    public void testCorrectOperation() {
        HttpRequestIntegrationFilter filter = new HttpRequestIntegrationFilter();
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

        filter.commitToContainer(new MockHttpServletRequest(principal, null),
            principal);
    }

    public void testHandlesIfHttpRequestIsNullForSomeReason() {
        HttpRequestIntegrationFilter filter = new HttpRequestIntegrationFilter();
        assertEquals(null, filter.extractFromContainer(null));
    }

    public void testHandlesIfThereIsNoPrincipal() {
        HttpRequestIntegrationFilter filter = new HttpRequestIntegrationFilter();
        assertEquals(null,
            filter.extractFromContainer(new MockHttpServletRequest(null, null)));
    }
}
