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

package org.springframework.security.authentication.rememberme;

import static org.assertj.core.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

/**
 * Tests {@link RememberMeAuthenticationToken}.
 *
 * @author Ben Alex
 */
public class RememberMeAuthenticationTokenTests {

	private static final List<GrantedAuthority> ROLES_12 = AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO");

	// ~ Methods
	// ========================================================================================================
	@Test
	public void testConstructorRejectsNulls() {
		try {
			new RememberMeAuthenticationToken(null, "Test", ROLES_12);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {

		}

		try {
			new RememberMeAuthenticationToken("key", null, ROLES_12);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {

		}

		try {
			List<GrantedAuthority> authsContainingNull = new ArrayList<>();
			authsContainingNull.add(null);
			new RememberMeAuthenticationToken("key", "Test", authsContainingNull);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {

		}
	}

	@Test
	public void testEqualsWhenEqual() {
		RememberMeAuthenticationToken token1 = new RememberMeAuthenticationToken("key", "Test", ROLES_12);
		RememberMeAuthenticationToken token2 = new RememberMeAuthenticationToken("key", "Test", ROLES_12);

		assertThat(token2).isEqualTo(token1);
	}

	@Test
	public void testGetters() {
		RememberMeAuthenticationToken token = new RememberMeAuthenticationToken("key", "Test", ROLES_12);

		assertThat(token.getKeyHash()).isEqualTo("key".hashCode());
		assertThat(token.getPrincipal()).isEqualTo("Test");
		assertThat(token.getCredentials()).isEqualTo("");
		assertThat(AuthorityUtils.authorityListToSet(token.getAuthorities())).contains("ROLE_ONE");
		assertThat(AuthorityUtils.authorityListToSet(token.getAuthorities())).contains("ROLE_TWO");
		assertThat(token.isAuthenticated()).isTrue();
	}

	@Test
	public void testNotEqualsDueToAbstractParentEqualsCheck() {
		RememberMeAuthenticationToken token1 = new RememberMeAuthenticationToken("key", "Test", ROLES_12);
		RememberMeAuthenticationToken token2 = new RememberMeAuthenticationToken("key", "DIFFERENT_PRINCIPAL",
				ROLES_12);

		assertThat(token1.equals(token2)).isFalse();
	}

	@Test
	public void testNotEqualsDueToDifferentAuthenticationClass() {
		RememberMeAuthenticationToken token1 = new RememberMeAuthenticationToken("key", "Test", ROLES_12);
		UsernamePasswordAuthenticationToken token2 = new UsernamePasswordAuthenticationToken("Test", "Password",
				ROLES_12);

		assertThat(token1.equals(token2)).isFalse();
	}

	@Test
	public void testNotEqualsDueToKey() {
		RememberMeAuthenticationToken token1 = new RememberMeAuthenticationToken("key", "Test", ROLES_12);
		RememberMeAuthenticationToken token2 = new RememberMeAuthenticationToken("DIFFERENT_KEY", "Test", ROLES_12);

		assertThat(token1.equals(token2)).isFalse();
	}

	@Test
	public void testSetAuthenticatedIgnored() {
		RememberMeAuthenticationToken token = new RememberMeAuthenticationToken("key", "Test", ROLES_12);
		assertThat(token.isAuthenticated()).isTrue();
		token.setAuthenticated(false);
		assertThat(!token.isAuthenticated()).isTrue();
	}

}
