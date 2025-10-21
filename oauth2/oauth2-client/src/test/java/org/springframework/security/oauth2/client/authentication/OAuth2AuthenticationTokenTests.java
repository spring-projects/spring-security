/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.client.authentication;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.TestOAuth2Users;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link OAuth2AuthenticationToken}.
 *
 * @author Joe Grandja
 */
public class OAuth2AuthenticationTokenTests {

	private OAuth2User principal;

	private Collection<? extends GrantedAuthority> authorities;

	private String authorizedClientRegistrationId;

	@BeforeEach
	public void setUp() {
		this.principal = mock(OAuth2User.class);
		this.authorities = Collections.emptyList();
		this.authorizedClientRegistrationId = "client-registration-1";
	}

	@Test
	public void constructorWhenPrincipalIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(
				() -> new OAuth2AuthenticationToken(null, this.authorities, this.authorizedClientRegistrationId));
	}

	@Test
	public void constructorWhenAuthoritiesIsNullThenCreated() {
		new OAuth2AuthenticationToken(this.principal, null, this.authorizedClientRegistrationId);
	}

	@Test
	public void constructorWhenAuthoritiesIsEmptyThenCreated() {
		new OAuth2AuthenticationToken(this.principal, Collections.emptyList(), this.authorizedClientRegistrationId);
	}

	@Test
	public void constructorWhenAuthorizedClientRegistrationIdIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new OAuth2AuthenticationToken(this.principal, this.authorities, null));
	}

	@Test
	public void constructorWhenAllParametersProvidedAndValidThenCreated() {
		OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(this.principal, this.authorities,
				this.authorizedClientRegistrationId);
		assertThat(authentication.getPrincipal()).isEqualTo(this.principal);
		assertThat(authentication.getCredentials()).isEqualTo("");
		assertThat(authentication.getAuthorities()).isEqualTo(this.authorities);
		assertThat(authentication.getAuthorizedClientRegistrationId()).isEqualTo(this.authorizedClientRegistrationId);
		assertThat(authentication.isAuthenticated()).isEqualTo(true);
	}

	@Test
	public void toBuilderWhenApplyThenCopies() {
		OAuth2AuthenticationToken factorOne = new OAuth2AuthenticationToken(TestOAuth2Users.create(),
				AuthorityUtils.createAuthorityList("FACTOR_ONE"), "alice");
		OAuth2AuthenticationToken factorTwo = new OAuth2AuthenticationToken(TestOAuth2Users.create(),
				AuthorityUtils.createAuthorityList("FACTOR_TWO"), "bob");
		OAuth2AuthenticationToken result = factorOne.toBuilder()
			.authorities((a) -> a.addAll(factorTwo.getAuthorities()))
			.principal(factorTwo.getPrincipal())
			.authorizedClientRegistrationId(factorTwo.getAuthorizedClientRegistrationId())
			.build();
		Set<String> authorities = AuthorityUtils.authorityListToSet(result.getAuthorities());
		assertThat(result.getPrincipal()).isSameAs(factorTwo.getPrincipal());
		assertThat(result.getAuthorizedClientRegistrationId()).isSameAs(factorTwo.getAuthorizedClientRegistrationId());
		assertThat(authorities).containsExactlyInAnyOrder("FACTOR_ONE", "FACTOR_TWO");
	}

}
