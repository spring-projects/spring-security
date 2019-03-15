/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.authentication;

import static org.junit.Assert.*;

import org.junit.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.*;


/**
 * Tests {@link AbstractAuthenticationToken}.
 *
 * @author Ben Alex
 */
public class AbstractAuthenticationTokenTests {
    //~ Instance fields ================================================================================================

    private List<GrantedAuthority> authorities = null;

    //~ Methods ========================================================================================================

    @Before
    public final void setUp() throws Exception {
        authorities = AuthorityUtils.createAuthorityList("ROLE_ONE","ROLE_TWO");
    }

    @Test(expected=UnsupportedOperationException.class)
    public void testAuthoritiesAreImmutable() {
        MockAuthenticationImpl token = new MockAuthenticationImpl("Test", "Password", authorities);
        List<GrantedAuthority> gotAuthorities = (List<GrantedAuthority>) token.getAuthorities();
        assertNotSame(authorities, gotAuthorities);

        gotAuthorities.set(0, new SimpleGrantedAuthority("ROLE_SUPER_USER"));
    }

    @Test
    public void testGetters() throws Exception {
        MockAuthenticationImpl token = new MockAuthenticationImpl("Test", "Password", authorities);
        assertEquals("Test", token.getPrincipal());
        assertEquals("Password", token.getCredentials());
        assertEquals("Test", token.getName());
    }

    @Test
    public void testHashCode() throws Exception {
        MockAuthenticationImpl token1 = new MockAuthenticationImpl("Test", "Password", authorities);
        MockAuthenticationImpl token2 = new MockAuthenticationImpl("Test", "Password", authorities);
        MockAuthenticationImpl token3 = new MockAuthenticationImpl(null, null, AuthorityUtils.NO_AUTHORITIES);
        assertEquals(token1.hashCode(), token2.hashCode());
        assertTrue(token1.hashCode() != token3.hashCode());

        token2.setAuthenticated(true);

        assertTrue(token1.hashCode() != token2.hashCode());
    }

    @Test
    public void testObjectsEquals() throws Exception {
        MockAuthenticationImpl token1 = new MockAuthenticationImpl("Test", "Password", authorities);
        MockAuthenticationImpl token2 = new MockAuthenticationImpl("Test", "Password", authorities);
        assertEquals(token1, token2);

        MockAuthenticationImpl token3 = new MockAuthenticationImpl("Test", "Password_Changed", authorities);
        assertTrue(!token1.equals(token3));

        MockAuthenticationImpl token4 = new MockAuthenticationImpl("Test_Changed", "Password", authorities);
        assertTrue(!token1.equals(token4));

        MockAuthenticationImpl token5 = new MockAuthenticationImpl("Test", "Password", AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO_CHANGED"));
        assertTrue(!token1.equals(token5));

        MockAuthenticationImpl token6 = new MockAuthenticationImpl("Test", "Password", AuthorityUtils.createAuthorityList("ROLE_ONE"));
        assertTrue(!token1.equals(token6));

        MockAuthenticationImpl token7 = new MockAuthenticationImpl("Test", "Password", null);
        assertTrue(!token1.equals(token7));
        assertTrue(!token7.equals(token1));

        assertTrue(!token1.equals(Integer.valueOf(100)));
    }

    @Test
    public void testSetAuthenticated() throws Exception {
        MockAuthenticationImpl token = new MockAuthenticationImpl("Test", "Password", authorities);
        assertTrue(!token.isAuthenticated());
        token.setAuthenticated(true);
        assertTrue(token.isAuthenticated());
    }

    @Test
    public void testToStringWithAuthorities() {
        MockAuthenticationImpl token = new MockAuthenticationImpl("Test", "Password", authorities);
        assertTrue(token.toString().lastIndexOf("ROLE_TWO") != -1);
    }

    @Test
    public void testToStringWithNullAuthorities() {
        MockAuthenticationImpl token = new MockAuthenticationImpl("Test", "Password", null);
        assertTrue(token.toString().lastIndexOf("Not granted any authorities") != -1);
    }

    //~ Inner Classes ==================================================================================================

    private class MockAuthenticationImpl extends AbstractAuthenticationToken {
        private Object credentials;
        private Object principal;

        public MockAuthenticationImpl(Object principal, Object credentials, List<GrantedAuthority> authorities) {
            super(authorities);
            this.principal = principal;
            this.credentials = credentials;
        }

        public Object getCredentials() {
            return this.credentials;
        }

        public Object getPrincipal() {
            return this.principal;
        }
    }
}
