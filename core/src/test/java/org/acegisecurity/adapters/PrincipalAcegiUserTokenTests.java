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

import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;


/**
 * Tests {@link net.sf.acegisecurity.adapters.PrincipalAcegiUserToken}
 *
 * @author Ben Alex
 * @version $Id$
 */
public class PrincipalAcegiUserTokenTests extends TestCase {
    //~ Constructors ===========================================================

    public PrincipalAcegiUserTokenTests() {
        super();
    }

    public PrincipalAcegiUserTokenTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(PrincipalAcegiUserTokenTests.class);
    }

    public void testGetters() throws Exception {
        PrincipalAcegiUserToken token = new PrincipalAcegiUserToken("my_password",
                "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        assertEquals("Test", token.getPrincipal());
        assertEquals("Password", token.getCredentials());
        assertEquals("my_password".hashCode(), token.getKeyHash());
    }

    public void testNoArgsConstructor() {
        PrincipalAcegiUserToken token = new PrincipalAcegiUserToken();
    }

    public void testObjectsEquals() throws Exception {
        PrincipalAcegiUserToken token1 = new PrincipalAcegiUserToken("my_password",
                "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        PrincipalAcegiUserToken token2 = new PrincipalAcegiUserToken("my_password",
                "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        System.out.println("Token 1:" + token1.toString() + " hash of pass "
            + token1.getKeyHash());
        System.out.println("Token 2:" + token2.toString() + " hash of pass "
            + token2.getKeyHash());
        assertEquals(token1, token2);

        PrincipalAcegiUserToken token3 = new PrincipalAcegiUserToken("my_password",
                "Test", "Password_Changed",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        assertTrue(!token1.equals(token3));

        PrincipalAcegiUserToken token4 = new PrincipalAcegiUserToken("my_password",
                "Test_Changed", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        assertTrue(!token1.equals(token4));

        PrincipalAcegiUserToken token5 = new PrincipalAcegiUserToken("password_changed",
                "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        assertTrue(!token1.equals(token5));

        PrincipalAcegiUserToken token6 = new PrincipalAcegiUserToken("my_password",
                "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO_CHANGED")});
        assertTrue(!token1.equals(token6));

        PrincipalAcegiUserToken token7 = new PrincipalAcegiUserToken("my_password",
                "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE")});
        assertTrue(!token1.equals(token7));
    }
}
