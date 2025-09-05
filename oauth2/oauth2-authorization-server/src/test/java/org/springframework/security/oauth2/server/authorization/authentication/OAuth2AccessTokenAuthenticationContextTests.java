/*
 * Copyright 2020-2024 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.authentication;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OAuth2AccessTokenAuthenticationContext}
 *
 * @author Dmitriy Dubson
 */
public class OAuth2AccessTokenAuthenticationContextTests {

	private final RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();

	private final OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(this.registeredClient)
		.build();

	private OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(this.registeredClient,
			ClientAuthenticationMethod.CLIENT_SECRET_BASIC, this.registeredClient.getClientSecret());

	private final OAuth2AccessTokenAuthenticationToken accessTokenAuthenticationToken = new OAuth2AccessTokenAuthenticationToken(
			this.registeredClient, this.clientPrincipal, this.authorization.getAccessToken().getToken(),
			this.authorization.getRefreshToken().getToken());

	@Test
	public void withWhenAuthenticationNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> OAuth2AccessTokenAuthenticationContext.with(null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("authentication cannot be null");
	}

	@Test
	public void setWhenValueNullThenThrowIllegalArgumentException() {
		OAuth2AccessTokenAuthenticationContext.Builder builder = OAuth2AccessTokenAuthenticationContext
			.with(this.accessTokenAuthenticationToken);

		assertThatThrownBy(() -> builder.accessTokenResponse(null)).isInstanceOf(IllegalArgumentException.class)
			.hasMessage("value cannot be null");
	}

	@Test
	public void buildWhenAllValuesProvidedThenAllValuesAreSet() {
		OAuth2AccessTokenResponse.Builder accessTokenResponseBuilder = OAuth2AccessTokenResponse
			.withToken(this.accessTokenAuthenticationToken.getAccessToken().getTokenValue());
		OAuth2AccessTokenAuthenticationContext context = OAuth2AccessTokenAuthenticationContext
			.with(this.accessTokenAuthenticationToken)
			.accessTokenResponse(accessTokenResponseBuilder)
			.build();

		assertThat(context.<Authentication>getAuthentication()).isEqualTo(this.accessTokenAuthenticationToken);
		assertThat(context.getAccessTokenResponse()).isEqualTo(accessTokenResponseBuilder);
	}

}
