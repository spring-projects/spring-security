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

package net.sf.acegisecurity.providers;

import junit.framework.TestCase;

import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;


/**
 * Tests {@link TestingAuthenticationToken}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class TestingAuthenticationTokenTests extends TestCase {
    //~ Constructors ===========================================================

    public TestingAuthenticationTokenTests() {
        super();
    }

    public TestingAuthenticationTokenTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(TestingAuthenticationTokenTests.class);
    }

    public void testAuthenticated() {
        TestingAuthenticationToken token = new TestingAuthenticationToken("Test",
                "Password", null);
        assertTrue(!token.isAuthenticated());
        token.setAuthenticated(true);
        assertTrue(token.isAuthenticated());
    }

    public void testGetters() {
        TestingAuthenticationToken token = new TestingAuthenticationToken("Test",
                "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        assertEquals("Test", token.getPrincipal());
        assertEquals("Password", token.getCredentials());
        assertEquals("ROLE_ONE", token.getAuthorities()[0].getAuthority());
        assertEquals("ROLE_TWO", token.getAuthorities()[1].getAuthority());
    }

    public void testNoArgConstructor() {
        try {
            new TestingAuthenticationToken();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }
}
