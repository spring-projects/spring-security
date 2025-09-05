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

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OAuth2TokenIntrospectionAuthenticationToken}.
 *
 * @author Gerardo Roza
 * @author Joe Grandja
 */
public class OAuth2TokenIntrospectionAuthenticationTokenTests {

	private String token = "token";

	private RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();

	private OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(this.registeredClient,
			ClientAuthenticationMethod.CLIENT_SECRET_BASIC, this.registeredClient.getClientSecret());

	private OAuth2TokenIntrospection tokenClaims = OAuth2TokenIntrospection.builder(true).build();

	@Test
	public void constructorWhenTokenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(
				() -> new OAuth2TokenIntrospectionAuthenticationToken(null, this.clientPrincipal, null, null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("token cannot be empty");
	}

	@Test
	public void constructorWhenClientPrincipalNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2TokenIntrospectionAuthenticationToken(this.token, null, null, null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("clientPrincipal cannot be null");
	}

	@Test
	public void constructorWhenAuthenticatedAndTokenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(
				() -> new OAuth2TokenIntrospectionAuthenticationToken(null, this.clientPrincipal, this.tokenClaims))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("token cannot be empty");
	}

	@Test
	public void constructorWhenAuthenticatedAndClientPrincipalNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2TokenIntrospectionAuthenticationToken(this.token, null, this.tokenClaims))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("clientPrincipal cannot be null");
	}

	@Test
	public void constructorWhenAuthenticatedAndTokenClaimsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(
				() -> new OAuth2TokenIntrospectionAuthenticationToken(this.token, this.clientPrincipal, null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("tokenClaims cannot be null");
	}

	@Test
	public void constructorWhenTokenProvidedThenCreated() {
		Map<String, Object> additionalParameters = Collections.singletonMap("custom-param", "custom-value");
		OAuth2TokenIntrospectionAuthenticationToken authentication = new OAuth2TokenIntrospectionAuthenticationToken(
				this.token, this.clientPrincipal, OAuth2TokenType.ACCESS_TOKEN.getValue(), additionalParameters);
		assertThat(authentication.getToken()).isEqualTo(this.token);
		assertThat(authentication.getPrincipal()).isEqualTo(this.clientPrincipal);
		assertThat(authentication.getCredentials().toString()).isEmpty();
		assertThat(authentication.getTokenTypeHint()).isEqualTo(OAuth2TokenType.ACCESS_TOKEN.getValue());
		assertThat(authentication.getAdditionalParameters()).containsExactlyInAnyOrderEntriesOf(additionalParameters);
		assertThat(authentication.getTokenClaims()).isNotNull();
		assertThat(authentication.getTokenClaims().isActive()).isFalse();
		assertThat(authentication.isAuthenticated()).isFalse();
	}

	@Test
	public void constructorWhenTokenClaimsProvidedThenCreated() {
		OAuth2TokenIntrospectionAuthenticationToken authentication = new OAuth2TokenIntrospectionAuthenticationToken(
				this.token, this.clientPrincipal, this.tokenClaims);
		assertThat(authentication.getToken()).isEqualTo(this.token);
		assertThat(authentication.getPrincipal()).isEqualTo(this.clientPrincipal);
		assertThat(authentication.getCredentials().toString()).isEmpty();
		assertThat(authentication.getTokenTypeHint()).isNull();
		assertThat(authentication.getAdditionalParameters()).isEmpty();
		assertThat(authentication.getTokenClaims()).isEqualTo(this.tokenClaims);
		assertThat(authentication.isAuthenticated()).isTrue();
	}

}
