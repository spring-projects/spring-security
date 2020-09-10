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

package org.springframework.security.authentication.anonymous;

import java.util.Collections;
import java.util.List;

import org.junit.Test;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests {@link AnonymousAuthenticationToken}.
 *
 * @author Ben Alex
 */
public class AnonymousAuthenticationTokenTests {

	private static final List<GrantedAuthority> ROLES_12 = AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO");

	@Test
	public void testConstructorRejectsNulls() {
		assertThatIllegalArgumentException().isThrownBy(() -> new AnonymousAuthenticationToken(null, "Test", ROLES_12));
		assertThatIllegalArgumentException().isThrownBy(() -> new AnonymousAuthenticationToken("key", null, ROLES_12));
		assertThatIllegalArgumentException().isThrownBy(() -> new AnonymousAuthenticationToken("key", "Test", null));
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new AnonymousAuthenticationToken("key", "Test", AuthorityUtils.NO_AUTHORITIES));
	}

	@Test
	public void testEqualsWhenEqual() {
		AnonymousAuthenticationToken token1 = new AnonymousAuthenticationToken("key", "Test", ROLES_12);
		AnonymousAuthenticationToken token2 = new AnonymousAuthenticationToken("key", "Test", ROLES_12);
		assertThat(token2).isEqualTo(token1);
	}

	@Test
	public void testGetters() {
		AnonymousAuthenticationToken token = new AnonymousAuthenticationToken("key", "Test", ROLES_12);
		assertThat(token.getKeyHash()).isEqualTo("key".hashCode());
		assertThat(token.getPrincipal()).isEqualTo("Test");
		assertThat(token.getCredentials()).isEqualTo("");
		assertThat(AuthorityUtils.authorityListToSet(token.getAuthorities())).contains("ROLE_ONE", "ROLE_TWO");
		assertThat(token.isAuthenticated()).isTrue();
	}

	@Test
	public void testNoArgConstructorDoesntExist() {
		assertThatExceptionOfType(NoSuchMethodException.class)
				.isThrownBy(() -> AnonymousAuthenticationToken.class.getDeclaredConstructor((Class[]) null));
	}

	@Test
	public void testNotEqualsDueToAbstractParentEqualsCheck() {
		AnonymousAuthenticationToken token1 = new AnonymousAuthenticationToken("key", "Test", ROLES_12);
		AnonymousAuthenticationToken token2 = new AnonymousAuthenticationToken("key", "DIFFERENT_PRINCIPAL", ROLES_12);
		assertThat(token1.equals(token2)).isFalse();
	}

	@Test
	public void testNotEqualsDueToDifferentAuthenticationClass() {
		AnonymousAuthenticationToken token1 = new AnonymousAuthenticationToken("key", "Test", ROLES_12);
		UsernamePasswordAuthenticationToken token2 = new UsernamePasswordAuthenticationToken("Test", "Password",
				ROLES_12);
		assertThat(token1.equals(token2)).isFalse();
	}

	@Test
	public void testNotEqualsDueToKey() {
		AnonymousAuthenticationToken token1 = new AnonymousAuthenticationToken("key", "Test", ROLES_12);
		AnonymousAuthenticationToken token2 = new AnonymousAuthenticationToken("DIFFERENT_KEY", "Test", ROLES_12);
		assertThat(token1.equals(token2)).isFalse();
	}

	@Test
	public void testSetAuthenticatedIgnored() {
		AnonymousAuthenticationToken token = new AnonymousAuthenticationToken("key", "Test", ROLES_12);
		assertThat(token.isAuthenticated()).isTrue();
		token.setAuthenticated(false);
		assertThat(!token.isAuthenticated()).isTrue();
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenNullAuthoritiesThenThrowIllegalArgumentException() {
		new AnonymousAuthenticationToken("key", "principal", null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenEmptyAuthoritiesThenThrowIllegalArgumentException() {
		new AnonymousAuthenticationToken("key", "principal", Collections.<GrantedAuthority>emptyList());
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenPrincipalIsEmptyStringThenThrowIllegalArgumentException() {
		new AnonymousAuthenticationToken("key", "", ROLES_12);
	}

}
