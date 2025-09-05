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
 * Tests for {@link OAuth2ClientCredentialsAuthenticationToken}.
 *
 * @author Alexey Nesterov
 */
public class OAuth2ClientCredentialsAuthenticationTokenTests {

	private final RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();

	private final OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
			this.registeredClient, ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
			this.registeredClient.getClientSecret());

	private Set<String> scopes = Collections.singleton("scope1");

	private Map<String, Object> additionalParameters = Collections.singletonMap("param1", "value1");

	@Test
	public void constructorWhenClientPrincipalNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(
				() -> new OAuth2ClientCredentialsAuthenticationToken(null, this.scopes, this.additionalParameters))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("clientPrincipal cannot be null");
	}

	@Test
	public void constructorWhenClientPrincipalProvidedThenCreated() {
		OAuth2ClientCredentialsAuthenticationToken authentication = new OAuth2ClientCredentialsAuthenticationToken(
				this.clientPrincipal, this.scopes, this.additionalParameters);

		assertThat(authentication.getGrantType()).isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS);
		assertThat(authentication.getPrincipal()).isEqualTo(this.clientPrincipal);
		assertThat(authentication.getCredentials().toString()).isEmpty();
		assertThat(authentication.getScopes()).isEqualTo(this.scopes);
		assertThat(authentication.getAdditionalParameters()).isEqualTo(this.additionalParameters);
	}

	@Test
	public void constructorWhenScopesProvidedThenCreated() {
		Set<String> expectedScopes = Collections.singleton("test-scope");

		OAuth2ClientCredentialsAuthenticationToken authentication = new OAuth2ClientCredentialsAuthenticationToken(
				this.clientPrincipal, expectedScopes, this.additionalParameters);

		assertThat(authentication.getGrantType()).isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS);
		assertThat(authentication.getPrincipal()).isEqualTo(this.clientPrincipal);
		assertThat(authentication.getCredentials().toString()).isEmpty();
		assertThat(authentication.getScopes()).isEqualTo(expectedScopes);
		assertThat(authentication.getAdditionalParameters()).isEqualTo(this.additionalParameters);
	}

}
