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

package org.acegisecurity.adapters;

import junit.framework.TestCase;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;


/**
 * Tests {@link AbstractAdapterAuthenticationToken}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AbstractAdapterAuthenticationTokenTests extends TestCase {
    //~ Constructors ===========================================================

    public AbstractAdapterAuthenticationTokenTests() {
        super();
    }

    public AbstractAdapterAuthenticationTokenTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(AbstractAdapterAuthenticationTokenTests.class);
    }

    public void testGetters() throws Exception {
        MockDecisionManagerImpl token = new MockDecisionManagerImpl("my_password",
                "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        assertEquals("Test", token.getPrincipal());
        assertEquals("Password", token.getCredentials());
        assertEquals("my_password".hashCode(), token.getKeyHash());
    }

    public void testIsUserInRole() throws Exception {
        MockDecisionManagerImpl token = new MockDecisionManagerImpl("my_password",
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
        try {
            new MockDecisionManagerImpl();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testObjectsEquals() throws Exception {
        MockDecisionManagerImpl token1 = new MockDecisionManagerImpl("my_password",
                "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        MockDecisionManagerImpl token2 = new MockDecisionManagerImpl("my_password",
                "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        assertEquals(token1, token2);

        MockDecisionManagerImpl token3 = new MockDecisionManagerImpl("my_password",
                "Test", "Password_Changed",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        assertTrue(!token1.equals(token3));

        MockDecisionManagerImpl token4 = new MockDecisionManagerImpl("my_password",
                "Test_Changed", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        assertTrue(!token1.equals(token4));

        MockDecisionManagerImpl token5 = new MockDecisionManagerImpl("password_changed",
                "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        assertTrue(!token1.equals(token5));

        MockDecisionManagerImpl token6 = new MockDecisionManagerImpl("my_password",
                "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO_CHANGED")});
        assertTrue(!token1.equals(token6));

        MockDecisionManagerImpl token7 = new MockDecisionManagerImpl("my_password",
                "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE")});
        assertTrue(!token1.equals(token7));

        assertTrue(!token1.equals(new Integer(100)));
    }

    public void testSetAuthenticatedAlwaysReturnsTrue()
        throws Exception {
        MockDecisionManagerImpl token = new MockDecisionManagerImpl("my_password",
                "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        assertTrue(token.isAuthenticated());
        token.setAuthenticated(false);
        assertTrue(token.isAuthenticated());
    }

    //~ Inner Classes ==========================================================

    private class MockDecisionManagerImpl
        extends AbstractAdapterAuthenticationToken {
        private String password;
        private String username;

        public MockDecisionManagerImpl(String key, String username,
            String password, GrantedAuthority[] authorities) {
            super(key, authorities);
            this.username = username;
            this.password = password;
        }

        private MockDecisionManagerImpl() {
            throw new IllegalArgumentException();
        }

        public Object getCredentials() {
            return this.password;
        }

        public Object getPrincipal() {
            return this.username;
        }
    }
}
