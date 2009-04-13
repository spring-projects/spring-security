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

package org.springframework.security.authentication.rememberme;

import java.util.ArrayList;
import java.util.List;

import junit.framework.TestCase;

import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthorityUtils;
import org.springframework.security.core.GrantedAuthority;

/**
 * Tests {@link RememberMeAuthenticationToken}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class RememberMeAuthenticationTokenTests extends TestCase {
    private static final List<GrantedAuthority> ROLES_12 = AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO");

    //~ Methods ========================================================================================================

    public void testConstructorRejectsNulls() {
        try {
            new RememberMeAuthenticationToken(null, "Test", ROLES_12);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            new RememberMeAuthenticationToken("key", null, ROLES_12);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            List<GrantedAuthority> authsContainingNull = new ArrayList<GrantedAuthority>();
            authsContainingNull.add(null);
            new RememberMeAuthenticationToken("key", "Test", authsContainingNull);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testEqualsWhenEqual() {
        RememberMeAuthenticationToken token1 = new RememberMeAuthenticationToken("key", "Test", ROLES_12);
        RememberMeAuthenticationToken token2 = new RememberMeAuthenticationToken("key", "Test", ROLES_12);

        assertEquals(token1, token2);
    }

    public void testGetters() {
        RememberMeAuthenticationToken token = new RememberMeAuthenticationToken("key", "Test",
                ROLES_12);

        assertEquals("key".hashCode(), token.getKeyHash());
        assertEquals("Test", token.getPrincipal());
        assertEquals("", token.getCredentials());
        assertEquals("ROLE_ONE", token.getAuthorities().get(0).getAuthority());
        assertEquals("ROLE_TWO", token.getAuthorities().get(1).getAuthority());
        assertTrue(token.isAuthenticated());
    }

    public void testNotEqualsDueToAbstractParentEqualsCheck() {
        RememberMeAuthenticationToken token1 = new RememberMeAuthenticationToken("key", "Test",ROLES_12);
        RememberMeAuthenticationToken token2 = new RememberMeAuthenticationToken("key", "DIFFERENT_PRINCIPAL",ROLES_12);

        assertFalse(token1.equals(token2));
    }

    public void testNotEqualsDueToDifferentAuthenticationClass() {
        RememberMeAuthenticationToken token1 = new RememberMeAuthenticationToken("key", "Test", ROLES_12);
        UsernamePasswordAuthenticationToken token2 = new UsernamePasswordAuthenticationToken("Test", "Password",ROLES_12);

        assertFalse(token1.equals(token2));
    }

    public void testNotEqualsDueToKey() {
        RememberMeAuthenticationToken token1 = new RememberMeAuthenticationToken("key", "Test", ROLES_12);
        RememberMeAuthenticationToken token2 = new RememberMeAuthenticationToken("DIFFERENT_KEY", "Test", ROLES_12);

        assertFalse(token1.equals(token2));
    }

    public void testSetAuthenticatedIgnored() {
        RememberMeAuthenticationToken token = new RememberMeAuthenticationToken("key", "Test", ROLES_12);
        assertTrue(token.isAuthenticated());
        token.setAuthenticated(false);
        assertTrue(!token.isAuthenticated());
    }
}
