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

package org.springframework.security.providers.x509;

import junit.framework.TestCase;


/**
 * Tests for {@link X509AuthenticationToken}.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class X509AuthenticationTokenTests extends TestCase {
    //~ Constructors ===================================================================================================

    public X509AuthenticationTokenTests() {}

    public X509AuthenticationTokenTests(String s) {
        super(s);
    }

    //~ Methods ========================================================================================================

    public void setUp() throws Exception {
        super.setUp();
    }

    public void testAuthenticated() throws Exception {
        X509AuthenticationToken token = X509TestUtils.createToken();
        assertTrue(!token.isAuthenticated());
        token.setAuthenticated(true);
        assertTrue(token.isAuthenticated());
    }

    public void testEquals() throws Exception {
        assertEquals(X509TestUtils.createToken(), X509TestUtils.createToken());
    }
}
