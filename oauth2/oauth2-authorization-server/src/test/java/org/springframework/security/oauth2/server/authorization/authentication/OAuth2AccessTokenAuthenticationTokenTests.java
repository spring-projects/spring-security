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

package org.springframework.security.oauth2.server.authorization.authentication;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Map;

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OAuth2AccessTokenAuthenticationToken}.
 *
 * @author Joe Grandja
 */
public class OAuth2AccessTokenAuthenticationTokenTests {

	private RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();

	private OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(this.registeredClient,
			ClientAuthenticationMethod.CLIENT_SECRET_BASIC, this.registeredClient.getClientSecret());

	private OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token",
			Instant.now(), Instant.now().plusSeconds(300));

	private OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", Instant.now(),
			Instant.now().plus(1, ChronoUnit.DAYS));

	private Map<String, Object> additionalParameters = Collections.singletonMap("custom-param", "custom-value");

	@Test
	public void constructorWhenRegisteredClientNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AccessTokenAuthenticationToken(null, this.clientPrincipal, this.accessToken))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("registeredClient cannot be null");
	}

	@Test
	public void constructorWhenClientPrincipalNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(
				() -> new OAuth2AccessTokenAuthenticationToken(this.registeredClient, null, this.accessToken))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("clientPrincipal cannot be null");
	}

	@Test
	public void constructorWhenAccessTokenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(
				() -> new OAuth2AccessTokenAuthenticationToken(this.registeredClient, this.clientPrincipal, null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("accessToken cannot be null");
	}

	@Test
	public void constructorWhenAdditionalParametersNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AccessTokenAuthenticationToken(this.registeredClient, this.clientPrincipal,
				this.accessToken, this.refreshToken, null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("additionalParameters cannot be null");
	}

	@Test
	public void constructorWhenAllValuesProvidedThenCreated() {
		OAuth2AccessTokenAuthenticationToken authentication = new OAuth2AccessTokenAuthenticationToken(
				this.registeredClient, this.clientPrincipal, this.accessToken, this.refreshToken,
				this.additionalParameters);
		assertThat(authentication.getPrincipal()).isEqualTo(this.clientPrincipal);
		assertThat(authentication.getCredentials().toString()).isEmpty();
		assertThat(authentication.getRegisteredClient()).isEqualTo(this.registeredClient);
		assertThat(authentication.getAccessToken()).isEqualTo(this.accessToken);
		assertThat(authentication.getRefreshToken()).isEqualTo(this.refreshToken);
		assertThat(authentication.getAdditionalParameters()).isEqualTo(this.additionalParameters);
	}

}
