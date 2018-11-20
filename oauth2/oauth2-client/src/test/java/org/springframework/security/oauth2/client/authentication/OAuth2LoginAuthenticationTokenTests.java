/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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

import org.junit.Before;
import org.junit.Test;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.user.OAuth2User;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.springframework.security.oauth2.client.registration.TestClientRegistrations.clientRegistration;
import static org.springframework.security.oauth2.core.TestOAuth2AccessTokens.noScopes;
import static org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationRequests.request;
import static org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationResponses.success;

/**
 * Tests for {@link OAuth2LoginAuthenticationToken}.
 *
 * @author Joe Grandja
 */
public class OAuth2LoginAuthenticationTokenTests {
	private OAuth2User principal;
	private Collection<? extends GrantedAuthority> authorities;
	private ClientRegistration clientRegistration;
	private OAuth2AuthorizationExchange authorizationExchange;
	private OAuth2AccessToken accessToken;

	@Before
	public void setUp() {
		this.principal = mock(OAuth2User.class);
		this.authorities = Collections.emptyList();
		this.clientRegistration = clientRegistration().build();
		this.authorizationExchange = new OAuth2AuthorizationExchange(
				request().build(), success().code("code").build());
		this.accessToken = noScopes();
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorAuthorizationRequestResponseWhenClientRegistrationIsNullThenThrowIllegalArgumentException() {
		new OAuth2LoginAuthenticationToken(null, this.authorizationExchange);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorAuthorizationRequestResponseWhenAuthorizationExchangeIsNullThenThrowIllegalArgumentException() {
		new OAuth2LoginAuthenticationToken(this.clientRegistration, null);
	}

	@Test
	public void constructorAuthorizationRequestResponseWhenAllParametersProvidedAndValidThenCreated() {
		OAuth2LoginAuthenticationToken authentication = new OAuth2LoginAuthenticationToken(
			this.clientRegistration, this.authorizationExchange);

		assertThat(authentication.getPrincipal()).isNull();
		assertThat(authentication.getCredentials()).isEqualTo("");
		assertThat(authentication.getAuthorities()).isEqualTo(Collections.emptyList());
		assertThat(authentication.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authentication.getAuthorizationExchange()).isEqualTo(this.authorizationExchange);
		assertThat(authentication.getAccessToken()).isNull();
		assertThat(authentication.isAuthenticated()).isEqualTo(false);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorTokenRequestResponseWhenClientRegistrationIsNullThenThrowIllegalArgumentException() {
		new OAuth2LoginAuthenticationToken(null, this.authorizationExchange, this.principal,
			this.authorities, this.accessToken);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorTokenRequestResponseWhenAuthorizationExchangeIsNullThenThrowIllegalArgumentException() {
		new OAuth2LoginAuthenticationToken(this.clientRegistration, null, this.principal,
			this.authorities, this.accessToken);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorTokenRequestResponseWhenPrincipalIsNullThenThrowIllegalArgumentException() {
		new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange, null,
			this.authorities, this.accessToken);
	}

	@Test
	public void constructorTokenRequestResponseWhenAuthoritiesIsNullThenCreated() {
		new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange,
			this.principal, null, this.accessToken);
	}

	@Test
	public void constructorTokenRequestResponseWhenAuthoritiesIsEmptyThenCreated() {
		new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange,
			this.principal, Collections.emptyList(), this.accessToken);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorTokenRequestResponseWhenAccessTokenIsNullThenThrowIllegalArgumentException() {
		new OAuth2LoginAuthenticationToken(this.clientRegistration, this.authorizationExchange, this.principal,
			this.authorities, null);
	}

	@Test
	public void constructorTokenRequestResponseWhenAllParametersProvidedAndValidThenCreated() {
		OAuth2LoginAuthenticationToken authentication = new OAuth2LoginAuthenticationToken(
			this.clientRegistration, this.authorizationExchange, this.principal, this.authorities, this.accessToken);

		assertThat(authentication.getPrincipal()).isEqualTo(this.principal);
		assertThat(authentication.getCredentials()).isEqualTo("");
		assertThat(authentication.getAuthorities()).isEqualTo(this.authorities);
		assertThat(authentication.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authentication.getAuthorizationExchange()).isEqualTo(this.authorizationExchange);
		assertThat(authentication.getAccessToken()).isEqualTo(this.accessToken);
		assertThat(authentication.isAuthenticated()).isEqualTo(true);
	}
}
