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

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link OAuth2ClientAuthenticationToken}.
 *
 * @author Joe Grandja
 * @author Anoop Garlapati
 */
public class OAuth2ClientAuthenticationTokenTests {

	@Test
	public void constructorWhenClientIdNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> new OAuth2ClientAuthenticationToken(null, ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
					"secret", null))
			.withMessage("clientId cannot be empty");
	}

	@Test
	public void constructorWhenClientAuthenticationMethodNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> new OAuth2ClientAuthenticationToken("clientId", null, "clientSecret", null))
			.withMessage("clientAuthenticationMethod cannot be null");
	}

	@Test
	public void constructorWhenRegisteredClientNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> new OAuth2ClientAuthenticationToken(null, ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
					"clientSecret"))
			.withMessage("registeredClient cannot be null");
	}

	@Test
	public void constructorWhenClientCredentialsProvidedThenCreated() {
		OAuth2ClientAuthenticationToken authentication = new OAuth2ClientAuthenticationToken("clientId",
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, "secret", null);
		assertThat(authentication.isAuthenticated()).isFalse();
		assertThat(authentication.getPrincipal().toString()).isEqualTo("clientId");
		assertThat(authentication.getCredentials()).isEqualTo("secret");
		assertThat(authentication.getRegisteredClient()).isNull();
		assertThat(authentication.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
	}

	@Test
	public void constructorWhenRegisteredClientProvidedThenCreated() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2ClientAuthenticationToken authentication = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		assertThat(authentication.isAuthenticated()).isTrue();
		assertThat(authentication.getPrincipal().toString()).isEqualTo(registeredClient.getClientId());
		assertThat(authentication.getCredentials().toString()).isEqualTo(registeredClient.getClientSecret());
		assertThat(authentication.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(authentication.getClientAuthenticationMethod())
			.isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
	}

}
