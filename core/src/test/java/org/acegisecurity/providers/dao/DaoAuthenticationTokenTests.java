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

package net.sf.acegisecurity.providers.dao;

import junit.framework.TestCase;

import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import java.util.Date;


/**
 * Tests {@link DaoAuthenticationToken}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class DaoAuthenticationTokenTests extends TestCase {
    //~ Constructors ===========================================================

    public DaoAuthenticationTokenTests() {
        super();
    }

    public DaoAuthenticationTokenTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(DaoAuthenticationTokenTests.class);
    }

    public void testConstructorRejectsNulls() {
        try {
            new DaoAuthenticationToken(null, new Date(), "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            new DaoAuthenticationToken("key", null, "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            new DaoAuthenticationToken("key", new Date(), null, "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            new DaoAuthenticationToken("key", new Date(), "Test", null,
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            new DaoAuthenticationToken("key", new Date(), "Test", "Password",
                null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            new DaoAuthenticationToken("key", new Date(), "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), null});
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testEqualsWhenEqual() {
        Date date = new Date();

        DaoAuthenticationToken token1 = new DaoAuthenticationToken("key", date,
                "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});

        DaoAuthenticationToken token2 = new DaoAuthenticationToken("key", date,
                "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});

        assertEquals(token1, token2);
    }

    public void testGetters() {
        Date date = new Date();
        DaoAuthenticationToken token = new DaoAuthenticationToken("key", date,
                "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        assertEquals("key".hashCode(), token.getKeyHash());
        assertEquals("Test", token.getPrincipal());
        assertEquals("Password", token.getCredentials());
        assertEquals("ROLE_ONE", token.getAuthorities()[0].getAuthority());
        assertEquals("ROLE_TWO", token.getAuthorities()[1].getAuthority());
        assertEquals(date, token.getExpires());
    }

    public void testNoArgConstructor() {
        try {
            new DaoAuthenticationToken();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testNotEqualsDueToAbstractParentEqualsCheck() {
        Date date = new Date();

        DaoAuthenticationToken token1 = new DaoAuthenticationToken("key", date,
                "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});

        DaoAuthenticationToken token2 = new DaoAuthenticationToken("key", date,
                "DIFFERENT_PRINCIPAL", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});

        assertTrue(!token1.equals(token2));
    }

    public void testNotEqualsDueToDifferentAuthenticationClass() {
        DaoAuthenticationToken token1 = new DaoAuthenticationToken("key",
                new Date(), "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});

        UsernamePasswordAuthenticationToken token2 = new UsernamePasswordAuthenticationToken("Test",
                "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        token2.setAuthenticated(true);

        assertTrue(!token1.equals(token2));
    }

    public void testNotEqualsDueToDifferentExpiresDate() {
        DaoAuthenticationToken token1 = new DaoAuthenticationToken("key",
                new Date(50000), "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});

        DaoAuthenticationToken token2 = new DaoAuthenticationToken("key",
                new Date(60000), "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});

        assertTrue(!token1.equals(token2));
    }

    public void testNotEqualsDueToKey() {
        Date date = new Date();

        DaoAuthenticationToken token1 = new DaoAuthenticationToken("key", date,
                "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});

        DaoAuthenticationToken token2 = new DaoAuthenticationToken("DIFFERENT_KEY",
                date, "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});

        assertTrue(!token1.equals(token2));
    }

    public void testSetAuthenticatedIgnored() {
        DaoAuthenticationToken token = new DaoAuthenticationToken("key",
                new Date(), "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        assertTrue(token.isAuthenticated());
        token.setAuthenticated(false); // ignored
        assertTrue(token.isAuthenticated());
    }

    public void testToString() {
        DaoAuthenticationToken token = new DaoAuthenticationToken("key",
                new Date(), "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});
        String result = token.toString();
        assertTrue(result.lastIndexOf("Expires:") != -1);
    }
}
