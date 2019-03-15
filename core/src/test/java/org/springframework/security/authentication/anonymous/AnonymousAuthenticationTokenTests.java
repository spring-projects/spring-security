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

package org.springframework.security.authentication.anonymous;

import java.util.List;

import junit.framework.TestCase;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;


/**
 * Tests {@link AnonymousAuthenticationToken}.
 *
 * @author Ben Alex
 */
public class AnonymousAuthenticationTokenTests extends TestCase {

    private final static List<GrantedAuthority> ROLES_12 = AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO");

    //~ Methods ========================================================================================================

    public void testConstructorRejectsNulls() {
        try {
            new AnonymousAuthenticationToken(null, "Test", ROLES_12);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }

        try {
            new AnonymousAuthenticationToken("key", null, ROLES_12);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }

        try {
            new AnonymousAuthenticationToken("key", "Test", (List<GrantedAuthority>)null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }

        try {
            new AnonymousAuthenticationToken("key", "Test", AuthorityUtils.NO_AUTHORITIES );
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }
    }

    public void testEqualsWhenEqual() {
        AnonymousAuthenticationToken token1 = new AnonymousAuthenticationToken("key", "Test", ROLES_12);
        AnonymousAuthenticationToken token2 = new AnonymousAuthenticationToken("key", "Test", ROLES_12);

        assertEquals(token1, token2);
    }

    public void testGetters() {
        AnonymousAuthenticationToken token = new AnonymousAuthenticationToken("key", "Test", ROLES_12);

        assertEquals("key".hashCode(), token.getKeyHash());
        assertEquals("Test", token.getPrincipal());
        assertEquals("", token.getCredentials());
        assertTrue(AuthorityUtils.authorityListToSet(token.getAuthorities()).contains("ROLE_ONE"));
        assertTrue(AuthorityUtils.authorityListToSet(token.getAuthorities()).contains("ROLE_TWO"));
        assertTrue(token.isAuthenticated());
    }

    public void testNoArgConstructorDoesntExist() {
        Class<?> clazz = AnonymousAuthenticationToken.class;

        try {
            clazz.getDeclaredConstructor((Class[]) null);
            fail("Should have thrown NoSuchMethodException");
        } catch (NoSuchMethodException expected) {
        }
    }

    public void testNotEqualsDueToAbstractParentEqualsCheck() {
        AnonymousAuthenticationToken token1 = new AnonymousAuthenticationToken("key", "Test", ROLES_12);
        AnonymousAuthenticationToken token2 = new AnonymousAuthenticationToken("key", "DIFFERENT_PRINCIPAL", ROLES_12);

        assertFalse(token1.equals(token2));
    }

    public void testNotEqualsDueToDifferentAuthenticationClass() {
        AnonymousAuthenticationToken token1 = new AnonymousAuthenticationToken("key", "Test", ROLES_12);
        UsernamePasswordAuthenticationToken token2 = new UsernamePasswordAuthenticationToken("Test", "Password", ROLES_12);

        assertFalse(token1.equals(token2));
    }

    public void testNotEqualsDueToKey() {
        AnonymousAuthenticationToken token1 = new AnonymousAuthenticationToken("key", "Test", ROLES_12);

        AnonymousAuthenticationToken token2 = new AnonymousAuthenticationToken("DIFFERENT_KEY", "Test", ROLES_12);

        assertFalse(token1.equals(token2));
    }

    public void testSetAuthenticatedIgnored() {
        AnonymousAuthenticationToken token = new AnonymousAuthenticationToken("key", "Test", ROLES_12);
        assertTrue(token.isAuthenticated());
        token.setAuthenticated(false);
        assertTrue(!token.isAuthenticated());
    }
}
