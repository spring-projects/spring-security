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

package net.sf.acegisecurity.adapters.jetty;

import junit.framework.TestCase;

import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;


/**
 * Tests {@link JettyAcegiUserToken}
 *
 * @author Ben Alex
 * @version $Id$
 */
public class JettyAcegiUserTokenTests extends TestCase {
    //~ Constructors ===========================================================

    public JettyAcegiUserTokenTests() {
        super();
    }

    public JettyAcegiUserTokenTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(JettyAcegiUserTokenTests.class);
    }

    public void testGetters() throws Exception {
        JettyAcegiUserToken token = new JettyAcegiUserToken("my_password",
                "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        assertEquals("Test", token.getPrincipal());
        assertEquals("Password", token.getCredentials());
        assertEquals("my_password".hashCode(), token.getKeyHash());
        assertEquals("Test", token.getName());
    }

    public void testIsUserInRole() throws Exception {
        JettyAcegiUserToken token = new JettyAcegiUserToken("my_password",
                "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        assertTrue(token.isUserInRole("ROLE_ONE"));
        assertTrue(token.isUserInRole("ROLE_TWO"));
        assertTrue(!token.isUserInRole(""));
        assertTrue(!token.isUserInRole("ROLE_ONE "));
        assertTrue(!token.isUserInRole("role_one"));
        assertTrue(!token.isUserInRole("ROLE_XXXX"));
    }

    public void testNoArgsConstructor() {
        JettyAcegiUserToken token = new JettyAcegiUserToken();
    }

    public void testObjectsEquals() throws Exception {
        JettyAcegiUserToken token1 = new JettyAcegiUserToken("my_password",
                "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        JettyAcegiUserToken token2 = new JettyAcegiUserToken("my_password",
                "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        assertEquals(token1, token2);

        JettyAcegiUserToken token3 = new JettyAcegiUserToken("my_password",
                "Test", "Password_Changed",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        assertTrue(!token1.equals(token3));

        JettyAcegiUserToken token4 = new JettyAcegiUserToken("my_password",
                "Test_Changed", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        assertTrue(!token1.equals(token4));

        JettyAcegiUserToken token5 = new JettyAcegiUserToken("password_changed",
                "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        assertTrue(!token1.equals(token5));

        JettyAcegiUserToken token6 = new JettyAcegiUserToken("my_password",
                "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO_CHANGED")});
        assertTrue(!token1.equals(token6));

        JettyAcegiUserToken token7 = new JettyAcegiUserToken("my_password",
                "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE")});
        assertTrue(!token1.equals(token7));

        assertTrue(!token1.equals(new Integer(100)));
    }

    public void testSetAuthenticatedAlwaysReturnsTrue()
        throws Exception {
        JettyAcegiUserToken token = new JettyAcegiUserToken("my_password",
                "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        assertTrue(token.isAuthenticated());
        token.setAuthenticated(false);
        assertTrue(token.isAuthenticated());
    }
}
