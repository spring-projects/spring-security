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

package net.sf.acegisecurity.providers;

import junit.framework.TestCase;

import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;


/**
 * Tests {@link UsernamePasswordAuthenticationToken}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class UsernamePasswordAuthenticationTokenTests extends TestCase {
    //~ Constructors ===========================================================

    public UsernamePasswordAuthenticationTokenTests() {
        super();
    }

    public UsernamePasswordAuthenticationTokenTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(UsernamePasswordAuthenticationTokenTests.class);
    }

    public void testAuthenticated() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test",
                "Password", null);

        // check default given we passed some GrantedAuthorty[]s (well, we passed null)
        assertTrue(token.isAuthenticated());

        // check explicit set to untrusted (we can safely go from trusted to untrusted, but not the reverse)
        token.setAuthenticated(false);
        assertTrue(!token.isAuthenticated());

        // Now let's create a UsernamePasswordAuthenticationToken without any GrantedAuthorty[]s (different constructor)
        token = new UsernamePasswordAuthenticationToken("Test", "Password");

        assertTrue(!token.isAuthenticated());

        // check we're allowed to still set it to untrusted
        token.setAuthenticated(false);
        assertTrue(!token.isAuthenticated());

        // check denied changing it to trusted
        try {
            token.setAuthenticated(true);
            fail("Should have prohibited setAuthenticated(true)");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testGetters() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("Test",
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
            new UsernamePasswordAuthenticationToken();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }
}
