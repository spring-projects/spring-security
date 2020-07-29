/*
 * Copyright 2002-2018 the original author or authors.
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

import java.util.Collections;

import org.junit.Before;
import org.junit.Test;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationRequests;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationResponses;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OAuth2AuthorizationCodeAuthenticationToken}.
 *
 * @author Joe Grandja
 */
public class OAuth2AuthorizationCodeAuthenticationTokenTests {

	private ClientRegistration clientRegistration;

	private OAuth2AuthorizationExchange authorizationExchange;

	private OAuth2AccessToken accessToken;

	@Before
	public void setUp() {
		this.clientRegistration = TestClientRegistrations.clientRegistration().build();
		this.authorizationExchange = new OAuth2AuthorizationExchange(TestOAuth2AuthorizationRequests.request().build(),
				TestOAuth2AuthorizationResponses.success().code("code").build());
		this.accessToken = TestOAuth2AccessTokens.noScopes();
	}

	@Test
	public void constructorAuthorizationRequestResponseWhenClientRegistrationIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationCodeAuthenticationToken(null, this.authorizationExchange))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorAuthorizationRequestResponseWhenAuthorizationExchangeIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationCodeAuthenticationToken(this.clientRegistration, null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorAuthorizationRequestResponseWhenAllParametersProvidedAndValidThenCreated() {
		OAuth2AuthorizationCodeAuthenticationToken authentication = new OAuth2AuthorizationCodeAuthenticationToken(
				this.clientRegistration, this.authorizationExchange);

		assertThat(authentication.getPrincipal()).isEqualTo(this.clientRegistration.getClientId());
		assertThat(authentication.getCredentials())
				.isEqualTo(this.authorizationExchange.getAuthorizationResponse().getCode());
		assertThat(authentication.getAuthorities()).isEqualTo(Collections.emptyList());
		assertThat(authentication.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authentication.getAuthorizationExchange()).isEqualTo(this.authorizationExchange);
		assertThat(authentication.getAccessToken()).isNull();
		assertThat(authentication.isAuthenticated()).isEqualTo(false);
	}

	@Test
	public void constructorTokenRequestResponseWhenClientRegistrationIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationCodeAuthenticationToken(null, this.authorizationExchange,
				this.accessToken)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorTokenRequestResponseWhenAuthorizationExchangeIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(
				() -> new OAuth2AuthorizationCodeAuthenticationToken(this.clientRegistration, null, this.accessToken))
						.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorTokenRequestResponseWhenAccessTokenIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationCodeAuthenticationToken(this.clientRegistration,
				this.authorizationExchange, null)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorTokenRequestResponseWhenAllParametersProvidedAndValidThenCreated() {
		OAuth2AuthorizationCodeAuthenticationToken authentication = new OAuth2AuthorizationCodeAuthenticationToken(
				this.clientRegistration, this.authorizationExchange, this.accessToken);

		assertThat(authentication.getPrincipal()).isEqualTo(this.clientRegistration.getClientId());
		assertThat(authentication.getCredentials()).isEqualTo(this.accessToken.getTokenValue());
		assertThat(authentication.getAuthorities()).isEqualTo(Collections.emptyList());
		assertThat(authentication.getClientRegistration()).isEqualTo(this.clientRegistration);
		assertThat(authentication.getAuthorizationExchange()).isEqualTo(this.authorizationExchange);
		assertThat(authentication.getAccessToken()).isEqualTo(this.accessToken);
		assertThat(authentication.isAuthenticated()).isEqualTo(true);
	}

}
