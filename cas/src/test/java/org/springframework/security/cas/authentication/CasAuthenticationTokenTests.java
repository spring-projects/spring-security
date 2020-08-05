/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.cas.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import java.util.Collections;
import java.util.List;

import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.AssertionImpl;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Tests {@link CasAuthenticationToken}.
 *
 * @author Ben Alex
 */
public class CasAuthenticationTokenTests {

	private final List<GrantedAuthority> ROLES = AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO");

	private UserDetails makeUserDetails() {
		return makeUserDetails("user");
	}

	private UserDetails makeUserDetails(final String name) {
		return new User(name, "password", true, true, true, true, ROLES);
	}

	@Test
	public void testConstructorRejectsNulls() {
		final Assertion assertion = new AssertionImpl("test");
		try {
			new CasAuthenticationToken(null, makeUserDetails(), "Password", ROLES, makeUserDetails(), assertion);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}

		try {
			new CasAuthenticationToken("key", null, "Password", ROLES, makeUserDetails(), assertion);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}

		try {
			new CasAuthenticationToken("key", makeUserDetails(), null, ROLES, makeUserDetails(), assertion);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}

		try {
			new CasAuthenticationToken("key", makeUserDetails(), "Password", ROLES, makeUserDetails(), null);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}

		try {
			new CasAuthenticationToken("key", makeUserDetails(), "Password", ROLES, null, assertion);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}

		try {
			new CasAuthenticationToken("key", makeUserDetails(), "Password",
					AuthorityUtils.createAuthorityList("ROLE_1", null), makeUserDetails(), assertion);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
		}
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenEmptyKeyThenThrowsException() {
		new CasAuthenticationToken("", "user", "password", Collections.<GrantedAuthority>emptyList(),
				new User("user", "password", Collections.<GrantedAuthority>emptyList()), null);
	}

	@Test
	public void testEqualsWhenEqual() {
		final Assertion assertion = new AssertionImpl("test");

		CasAuthenticationToken token1 = new CasAuthenticationToken("key", makeUserDetails(), "Password", ROLES,
				makeUserDetails(), assertion);

		CasAuthenticationToken token2 = new CasAuthenticationToken("key", makeUserDetails(), "Password", ROLES,
				makeUserDetails(), assertion);

		assertThat(token2).isEqualTo(token1);
	}

	@Test
	public void testGetters() {
		// Build the proxy list returned in the ticket from CAS
		final Assertion assertion = new AssertionImpl("test");
		CasAuthenticationToken token = new CasAuthenticationToken("key", makeUserDetails(), "Password", ROLES,
				makeUserDetails(), assertion);
		assertThat(token.getKeyHash()).isEqualTo("key".hashCode());
		assertThat(token.getPrincipal()).isEqualTo(makeUserDetails());
		assertThat(token.getCredentials()).isEqualTo("Password");
		assertThat(token.getAuthorities()).contains(new SimpleGrantedAuthority("ROLE_ONE"));
		assertThat(token.getAuthorities()).contains(new SimpleGrantedAuthority("ROLE_TWO"));
		assertThat(token.getAssertion()).isEqualTo(assertion);
		assertThat(token.getUserDetails().getUsername()).isEqualTo(makeUserDetails().getUsername());
	}

	@Test
	public void testNoArgConstructorDoesntExist() {
		try {
			CasAuthenticationToken.class.getDeclaredConstructor((Class[]) null);
			fail("Should have thrown NoSuchMethodException");
		}
		catch (NoSuchMethodException expected) {

		}
	}

	@Test
	public void testNotEqualsDueToAbstractParentEqualsCheck() {
		final Assertion assertion = new AssertionImpl("test");

		CasAuthenticationToken token1 = new CasAuthenticationToken("key", makeUserDetails(), "Password", ROLES,
				makeUserDetails(), assertion);

		CasAuthenticationToken token2 = new CasAuthenticationToken("key", makeUserDetails("OTHER_NAME"), "Password",
				ROLES, makeUserDetails(), assertion);

		assertThat(!token1.equals(token2)).isTrue();
	}

	@Test
	public void testNotEqualsDueToDifferentAuthenticationClass() {
		final Assertion assertion = new AssertionImpl("test");

		CasAuthenticationToken token1 = new CasAuthenticationToken("key", makeUserDetails(), "Password", ROLES,
				makeUserDetails(), assertion);

		UsernamePasswordAuthenticationToken token2 = new UsernamePasswordAuthenticationToken("Test", "Password", ROLES);
		assertThat(!token1.equals(token2)).isTrue();
	}

	@Test
	public void testNotEqualsDueToKey() {
		final Assertion assertion = new AssertionImpl("test");

		CasAuthenticationToken token1 = new CasAuthenticationToken("key", makeUserDetails(), "Password", ROLES,
				makeUserDetails(), assertion);

		CasAuthenticationToken token2 = new CasAuthenticationToken("DIFFERENT_KEY", makeUserDetails(), "Password",
				ROLES, makeUserDetails(), assertion);

		assertThat(!token1.equals(token2)).isTrue();
	}

	@Test
	public void testNotEqualsDueToAssertion() {
		final Assertion assertion = new AssertionImpl("test");
		final Assertion assertion2 = new AssertionImpl("test");

		CasAuthenticationToken token1 = new CasAuthenticationToken("key", makeUserDetails(), "Password", ROLES,
				makeUserDetails(), assertion);

		CasAuthenticationToken token2 = new CasAuthenticationToken("key", makeUserDetails(), "Password", ROLES,
				makeUserDetails(), assertion2);

		assertThat(!token1.equals(token2)).isTrue();
	}

	@Test
	public void testSetAuthenticated() {
		final Assertion assertion = new AssertionImpl("test");
		CasAuthenticationToken token = new CasAuthenticationToken("key", makeUserDetails(), "Password", ROLES,
				makeUserDetails(), assertion);
		assertThat(token.isAuthenticated()).isTrue();
		token.setAuthenticated(false);
		assertThat(!token.isAuthenticated()).isTrue();
	}

	@Test
	public void testToString() {
		final Assertion assertion = new AssertionImpl("test");
		CasAuthenticationToken token = new CasAuthenticationToken("key", makeUserDetails(), "Password", ROLES,
				makeUserDetails(), assertion);
		String result = token.toString();
		assertThat(result.lastIndexOf("Credentials (Service/Proxy Ticket):") != -1).isTrue();
	}

}
