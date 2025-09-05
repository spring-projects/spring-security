/*
 * Copyright 2020-2022 the original author or authors.
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

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OAuth2RefreshTokenAuthenticationToken}.
 *
 * @author Alexey Nesterov
 * @since 0.0.3
 */
public class OAuth2RefreshTokenAuthenticationTokenTests {

	private RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();

	private OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(this.registeredClient,
			ClientAuthenticationMethod.CLIENT_SECRET_BASIC, this.registeredClient.getClientSecret());

	private Set<String> scopes = Collections.singleton("scope1");

	private Map<String, Object> additionalParameters = Collections.singletonMap("param1", "value1");

	@Test
	public void constructorWhenRefreshTokenNullOrEmptyThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2RefreshTokenAuthenticationToken(null, this.clientPrincipal, this.scopes,
				this.additionalParameters))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("refreshToken cannot be empty");
		assertThatThrownBy(() -> new OAuth2RefreshTokenAuthenticationToken("", this.clientPrincipal, this.scopes,
				this.additionalParameters))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("refreshToken cannot be empty");
	}

	@Test
	public void constructorWhenClientPrincipalNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2RefreshTokenAuthenticationToken("refresh-token", null, this.scopes,
				this.additionalParameters))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("clientPrincipal cannot be null");
	}

	@Test
	public void constructorWhenScopesProvidedThenCreated() {
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				"refresh-token", this.clientPrincipal, this.scopes, this.additionalParameters);
		assertThat(authentication.getGrantType()).isEqualTo(AuthorizationGrantType.REFRESH_TOKEN);
		assertThat(authentication.getRefreshToken()).isEqualTo("refresh-token");
		assertThat(authentication.getPrincipal()).isEqualTo(this.clientPrincipal);
		assertThat(authentication.getCredentials().toString()).isEmpty();
		assertThat(authentication.getScopes()).isEqualTo(this.scopes);
		assertThat(authentication.getAdditionalParameters()).isEqualTo(this.additionalParameters);
	}

}
