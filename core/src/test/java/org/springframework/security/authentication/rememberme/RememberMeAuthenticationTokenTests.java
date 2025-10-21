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

import java.util.Arrays;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.PasswordEncodedUser;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests {@link RememberMeAuthenticationToken}.
 *
 * @author Ben Alex
 */
public class RememberMeAuthenticationTokenTests {

	private static final List<GrantedAuthority> ROLES_12 = AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO");

	@Test
	public void testConstructorRejectsNulls() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new RememberMeAuthenticationToken(null, "Test", ROLES_12));
		assertThatIllegalArgumentException().isThrownBy(() -> new RememberMeAuthenticationToken("key", null, ROLES_12));
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new RememberMeAuthenticationToken("key", "Test", Arrays.asList((GrantedAuthority) null)));
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
		UsernamePasswordAuthenticationToken token2 = UsernamePasswordAuthenticationToken.authenticated("Test",
				"Password", ROLES_12);
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

	@Test
	public void toBuilderWhenApplyThenCopies() {
		RememberMeAuthenticationToken factorOne = new RememberMeAuthenticationToken("key", PasswordEncodedUser.user(),
				AuthorityUtils.createAuthorityList("FACTOR_ONE"));
		RememberMeAuthenticationToken factorTwo = new RememberMeAuthenticationToken("yek", PasswordEncodedUser.admin(),
				AuthorityUtils.createAuthorityList("FACTOR_TWO"));
		RememberMeAuthenticationToken authentication = factorOne.toBuilder()
			.authorities((a) -> a.addAll(factorTwo.getAuthorities()))
			.key("yek")
			.principal(factorTwo.getPrincipal())
			.build();
		Set<String> authorities = AuthorityUtils.authorityListToSet(authentication.getAuthorities());
		assertThat(authentication.getKeyHash()).isEqualTo(factorTwo.getKeyHash());
		assertThat(authentication.getPrincipal()).isEqualTo(factorTwo.getPrincipal());
		assertThat(authorities).containsExactlyInAnyOrder("FACTOR_ONE", "FACTOR_TWO");
	}

}
