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

package org.springframework.security.providers.cas;

import junit.framework.TestCase;

import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.AssertionImpl;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;

import org.springframework.security.providers.UsernamePasswordAuthenticationToken;

import org.springframework.security.userdetails.User;
import org.springframework.security.userdetails.UserDetails;

/**
 * Tests {@link CasAuthenticationToken}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class CasAuthenticationTokenTests extends TestCase {
    //~ Constructors ===================================================================================================

    public CasAuthenticationTokenTests() {
        super();
    }

    public CasAuthenticationTokenTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(CasAuthenticationTokenTests.class);
    }

    private UserDetails makeUserDetails() {
        return makeUserDetails("user");
    }

    private UserDetails makeUserDetails(final String name) {
        return new User(name, "password", true, true, true, true,
            new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")});
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testConstructorRejectsNulls() {
    	final Assertion assertion = new AssertionImpl("test");
        try {
            new CasAuthenticationToken(null, makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")},
                makeUserDetails(), assertion);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            new CasAuthenticationToken("key", null, "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")},
                makeUserDetails(), assertion);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            new CasAuthenticationToken("key", makeUserDetails(), null,
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")},
                makeUserDetails(), assertion);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            new CasAuthenticationToken("key", makeUserDetails(), "Password", null, makeUserDetails(), assertion);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            new CasAuthenticationToken("key", makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")},
                makeUserDetails(), null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            new CasAuthenticationToken("key", makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")},
                null, assertion);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
   

        try {
            new CasAuthenticationToken("key", makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), null, new GrantedAuthorityImpl("ROLE_TWO")},
                makeUserDetails(), assertion);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testEqualsWhenEqual() {
    	final Assertion assertion = new AssertionImpl("test");

        CasAuthenticationToken token1 = new CasAuthenticationToken("key", makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")},
                makeUserDetails(), assertion);

        CasAuthenticationToken token2 = new CasAuthenticationToken("key", makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")},
                makeUserDetails(), assertion);

        assertEquals(token1, token2);
    }

    public void testGetters() {
        // Build the proxy list returned in the ticket from CAS
    	final Assertion assertion = new AssertionImpl("test");
        CasAuthenticationToken token = new CasAuthenticationToken("key", makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")},
                makeUserDetails(), assertion);
        assertEquals("key".hashCode(), token.getKeyHash());
        assertEquals(makeUserDetails(), token.getPrincipal());
        assertEquals("Password", token.getCredentials());
        assertEquals("ROLE_ONE", token.getAuthorities()[0].getAuthority());
        assertEquals("ROLE_TWO", token.getAuthorities()[1].getAuthority());
        assertEquals(assertion, token.getAssertion());
        assertEquals(makeUserDetails().getUsername(), token.getUserDetails().getUsername());
    }

    public void testNoArgConstructorDoesntExist() {
        Class clazz = CasAuthenticationToken.class;

        try {
            clazz.getDeclaredConstructor((Class[]) null);
            fail("Should have thrown NoSuchMethodException");
        } catch (NoSuchMethodException expected) {
            assertTrue(true);
        }
    }

    public void testNotEqualsDueToAbstractParentEqualsCheck() {
    	final Assertion assertion = new AssertionImpl("test");

        CasAuthenticationToken token1 = new CasAuthenticationToken("key", makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")},
                makeUserDetails(), assertion);

        CasAuthenticationToken token2 = new CasAuthenticationToken("key", makeUserDetails("OTHER_NAME"), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")},
                makeUserDetails(), assertion);

        assertTrue(!token1.equals(token2));
    }

    public void testNotEqualsDueToDifferentAuthenticationClass() {
    	final Assertion assertion = new AssertionImpl("test");

        CasAuthenticationToken token1 = new CasAuthenticationToken("key", makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")},
                makeUserDetails(), assertion);

        UsernamePasswordAuthenticationToken token2 = new UsernamePasswordAuthenticationToken("Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")});

        assertTrue(!token1.equals(token2));
    }

    public void testNotEqualsDueToKey() {
    	final Assertion assertion = new AssertionImpl("test");

        CasAuthenticationToken token1 = new CasAuthenticationToken("key", makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")},
                makeUserDetails(), assertion);

        CasAuthenticationToken token2 = new CasAuthenticationToken("DIFFERENT_KEY", makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")},
                makeUserDetails(), assertion);

        assertTrue(!token1.equals(token2));
    }

    public void testNotEqualsDueToAssertion() {
    	final Assertion assertion = new AssertionImpl("test");
    	final Assertion assertion2 = new AssertionImpl("test");

        CasAuthenticationToken token1 = new CasAuthenticationToken("key", makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")},
                makeUserDetails(), assertion);

        CasAuthenticationToken token2 = new CasAuthenticationToken("key", makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")},
                makeUserDetails(), assertion2);

        assertTrue(!token1.equals(token2));
    }

    public void testSetAuthenticated() {
    	final Assertion assertion = new AssertionImpl("test");
        CasAuthenticationToken token = new CasAuthenticationToken("key", makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")},
                makeUserDetails(), assertion);
        assertTrue(token.isAuthenticated());
        token.setAuthenticated(false);
        assertTrue(!token.isAuthenticated());
    }

    public void testToString() {
    	final Assertion assertion = new AssertionImpl("test");
        CasAuthenticationToken token = new CasAuthenticationToken("key", makeUserDetails(), "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")},
                makeUserDetails(), assertion);
        String result = token.toString();
        assertTrue(result.lastIndexOf("Credentials (Service/Proxy Ticket):") != -1);
    }
}
