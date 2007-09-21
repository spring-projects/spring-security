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

package org.springframework.security;

import junit.framework.TestCase;

import org.springframework.security.providers.TestingAuthenticationToken;


/**
 * Tests {@link AbstractAuthenticationManager}.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class AbstractAuthenticationManagerTests extends TestCase {
    //~ Constructors ===================================================================================================

    public AbstractAuthenticationManagerTests() {
        super();
    }

    public AbstractAuthenticationManagerTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    /**
     * Creates an AuthenticationManager which will return a token with the given details object set on it.
     *
     * @param resultDetails DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    private AuthenticationManager createAuthenticationManager(final Object resultDetails) {
        return new AbstractAuthenticationManager() {
                protected Authentication doAuthentication(Authentication authentication)
                    throws AuthenticationException {
                    TestingAuthenticationToken token = createAuthenticationToken();
                    token.setDetails(resultDetails);

                    return token;
                }
            };
    }

    private TestingAuthenticationToken createAuthenticationToken() {
        return new TestingAuthenticationToken("name", "password", new GrantedAuthorityImpl[0]);
    }

    public void testDetailsAreNotSetOnAuthenticationTokenIfAlreadySetByProvider() {
        Object requestDetails = new String("(Request Details)");
        Object resultDetails = new String("(Result Details)");
        AuthenticationManager authMgr = createAuthenticationManager(resultDetails);

        TestingAuthenticationToken request = createAuthenticationToken();
        request.setDetails(requestDetails);

        Authentication result = authMgr.authenticate(request);
        assertEquals(resultDetails, result.getDetails());
    }

    public void testDetailsAreSetOnAuthenticationTokenIfNotAlreadySetByProvider() {
        AuthenticationManager authMgr = createAuthenticationManager(null);
        Object details = new Object();

        TestingAuthenticationToken request = createAuthenticationToken();
        request.setDetails(details);

        Authentication result = authMgr.authenticate(request);
        assertEquals(details, result.getDetails());
    }
}
