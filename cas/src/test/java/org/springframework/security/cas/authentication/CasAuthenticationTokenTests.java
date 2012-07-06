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

package org.springframework.security.cas.authentication;

import junit.framework.TestCase;

import org.jasig.cas.client.authentication.AttributePrincipal;
import org.jasig.cas.client.authentication.AttributePrincipalImpl;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.AssertionImpl;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.*;

/**
 * Tests {@link CasAuthenticationToken}.
 *
 * @author Ben Alex
 */
public class CasAuthenticationTokenTests extends TestCase {
    private final List<GrantedAuthority> ROLES = AuthorityUtils.createAuthorityList("ROLE_ONE","ROLE_TWO");

    private UserDetails makeUserDetails() {
        return makeUserDetails("user");
    }

    private UserDetails makeUserDetails(final String name) {
        return new User(name, "password", true, true, true, true, ROLES);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testConstructorRejectsNulls() {
        final Assertion assertion = new AssertionImpl("test");
        try {
            new CasAuthenticationToken(null, makeUserDetails(), "Password", ROLES, makeUserDetails(), assertion, CasAuthenticationProviderTests.TEST_REMEMBERME_ATTRIBUTE_NAME);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }

        try {
            new CasAuthenticationToken("key", null, "Password", ROLES, makeUserDetails(), assertion, CasAuthenticationProviderTests.TEST_REMEMBERME_ATTRIBUTE_NAME);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }

        try {
            new CasAuthenticationToken("key", makeUserDetails(), null, ROLES, makeUserDetails(), assertion, CasAuthenticationProviderTests.TEST_REMEMBERME_ATTRIBUTE_NAME);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }

        try {
            new CasAuthenticationToken("key", makeUserDetails(), "Password", ROLES, makeUserDetails(), null, CasAuthenticationProviderTests.TEST_REMEMBERME_ATTRIBUTE_NAME);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }

        try {
            new CasAuthenticationToken("key", makeUserDetails(), "Password", ROLES, null, assertion, CasAuthenticationProviderTests.TEST_REMEMBERME_ATTRIBUTE_NAME);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
        }

        try {
            new CasAuthenticationToken("key", makeUserDetails(), "Password", AuthorityUtils.createAuthorityList("ROLE_1", null),
                                       makeUserDetails(), assertion, CasAuthenticationProviderTests.TEST_REMEMBERME_ATTRIBUTE_NAME);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }

        try {
            new CasAuthenticationToken("key", makeUserDetails(), "Password", ROLES, makeUserDetails(), assertion, null);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
}

    public void testEqualsWhenEqual() {
        final Assertion assertion = new AssertionImpl("test");

        CasAuthenticationToken token1 = new CasAuthenticationToken("key", makeUserDetails(), "Password", ROLES,
                makeUserDetails(), assertion, CasAuthenticationProviderTests.TEST_REMEMBERME_ATTRIBUTE_NAME);

        CasAuthenticationToken token2 = new CasAuthenticationToken("key", makeUserDetails(), "Password", ROLES,
                makeUserDetails(), assertion, CasAuthenticationProviderTests.TEST_REMEMBERME_ATTRIBUTE_NAME);

        assertEquals(token1, token2);
    }

    public void testGetters() {
        // Build the proxy list returned in the ticket from CAS
        final Assertion assertion = new AssertionImpl("test");
        CasAuthenticationToken token = new CasAuthenticationToken("key", makeUserDetails(), "Password", ROLES,
                makeUserDetails(), assertion, CasAuthenticationProviderTests.TEST_REMEMBERME_ATTRIBUTE_NAME);
        assertEquals("key".hashCode(), token.getKeyHash());
        assertEquals(makeUserDetails(), token.getPrincipal());
        assertEquals("Password", token.getCredentials());
        assertTrue(token.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_ONE")));
        assertTrue(token.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_TWO")));
        assertEquals(assertion, token.getAssertion());
        assertEquals(makeUserDetails().getUsername(), token.getUserDetails().getUsername());
        assertFalse(token.isRememberMe());
    }

    public void testNoArgConstructorDoesntExist() {
        try {
            CasAuthenticationToken.class.getDeclaredConstructor((Class[]) null);
            fail("Should have thrown NoSuchMethodException");
        } catch (NoSuchMethodException expected) {
            assertTrue(true);
        }
    }

    public void testNotEqualsDueToAbstractParentEqualsCheck() {
        final Assertion assertion = new AssertionImpl("test");

        CasAuthenticationToken token1 = new CasAuthenticationToken("key", makeUserDetails(), "Password", ROLES,
                makeUserDetails(), assertion, CasAuthenticationProviderTests.TEST_REMEMBERME_ATTRIBUTE_NAME);

        CasAuthenticationToken token2 = new CasAuthenticationToken("key", makeUserDetails("OTHER_NAME"), "Password",
                ROLES, makeUserDetails(), assertion, CasAuthenticationProviderTests.TEST_REMEMBERME_ATTRIBUTE_NAME);

        assertTrue(!token1.equals(token2));
    }

    public void testNotEqualsDueToDifferentAuthenticationClass() {
        final Assertion assertion = new AssertionImpl("test");

        CasAuthenticationToken token1 = new CasAuthenticationToken("key", makeUserDetails(), "Password", ROLES,
                makeUserDetails(), assertion, CasAuthenticationProviderTests.TEST_REMEMBERME_ATTRIBUTE_NAME);

        UsernamePasswordAuthenticationToken token2 = new UsernamePasswordAuthenticationToken("Test", "Password", ROLES);
        assertTrue(!token1.equals(token2));
    }

    public void testNotEqualsDueToKey() {
        final Assertion assertion = new AssertionImpl("test");

        CasAuthenticationToken token1 = new CasAuthenticationToken("key", makeUserDetails(), "Password", ROLES,
                makeUserDetails(), assertion, CasAuthenticationProviderTests.TEST_REMEMBERME_ATTRIBUTE_NAME);

        CasAuthenticationToken token2 = new CasAuthenticationToken("DIFFERENT_KEY", makeUserDetails(), "Password",
                ROLES, makeUserDetails(), assertion, CasAuthenticationProviderTests.TEST_REMEMBERME_ATTRIBUTE_NAME);

        assertTrue(!token1.equals(token2));
    }

    public void testNotEqualsDueToAssertion() {
        final Assertion assertion = new AssertionImpl("test");
        final Assertion assertion2 = new AssertionImpl("test");

        CasAuthenticationToken token1 = new CasAuthenticationToken("key", makeUserDetails(), "Password", ROLES,
                makeUserDetails(), assertion, CasAuthenticationProviderTests.TEST_REMEMBERME_ATTRIBUTE_NAME);

        CasAuthenticationToken token2 = new CasAuthenticationToken("key", makeUserDetails(), "Password", ROLES,
                makeUserDetails(), assertion2, CasAuthenticationProviderTests.TEST_REMEMBERME_ATTRIBUTE_NAME);

        assertTrue(!token1.equals(token2));
    }

    public void testSetAuthenticated() {
        final Assertion assertion = new AssertionImpl("test");
        CasAuthenticationToken token = new CasAuthenticationToken("key", makeUserDetails(), "Password", ROLES,
                makeUserDetails(), assertion, CasAuthenticationProviderTests.TEST_REMEMBERME_ATTRIBUTE_NAME);
        assertTrue(token.isAuthenticated());
        token.setAuthenticated(false);
        assertTrue(!token.isAuthenticated());
    }

    @SuppressWarnings({
        "rawtypes", "unchecked"
    })
    public void testIsRemember() {
        Map attributes = new HashMap();
        attributes.put(CasAuthenticationProviderTests.TEST_REMEMBERME_ATTRIBUTE_NAME, "true");
        final AttributePrincipal principal = new AttributePrincipalImpl("test", attributes);
        final Assertion assertion = new AssertionImpl(principal);
        CasAuthenticationToken token = new CasAuthenticationToken("key", makeUserDetails(), "Password", ROLES,
                makeUserDetails(), assertion, CasAuthenticationProviderTests.TEST_REMEMBERME_ATTRIBUTE_NAME);
        assertTrue(token.isRememberMe());
    }

    public void testToString() {
        final Assertion assertion = new AssertionImpl("test");
        CasAuthenticationToken token = new CasAuthenticationToken("key", makeUserDetails(), "Password",ROLES,
                makeUserDetails(), assertion, CasAuthenticationProviderTests.TEST_REMEMBERME_ATTRIBUTE_NAME);
        String result = token.toString();
        assertTrue(result.lastIndexOf("Credentials (Service/Proxy Ticket):") != -1);
    }
}
