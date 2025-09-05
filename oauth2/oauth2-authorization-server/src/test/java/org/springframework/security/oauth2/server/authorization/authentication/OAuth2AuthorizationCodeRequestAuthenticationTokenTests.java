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

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link OAuth2AuthorizationCodeRequestAuthenticationToken}.
 *
 * @author Joe Grandja
 */
public class OAuth2AuthorizationCodeRequestAuthenticationTokenTests {

	private static final String AUTHORIZATION_URI = "https://provider.com/oauth2/authorize";

	private static final RegisteredClient REGISTERED_CLIENT = TestRegisteredClients.registeredClient().build();

	private static final TestingAuthenticationToken PRINCIPAL = new TestingAuthenticationToken("principalName",
			"password");

	private static final OAuth2AuthorizationCode AUTHORIZATION_CODE = new OAuth2AuthorizationCode("code", Instant.now(),
			Instant.now().plus(5, ChronoUnit.MINUTES));

	@Test
	public void constructorWhenAuthorizationUriNotProvidedThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationCodeRequestAuthenticationToken(null,
				REGISTERED_CLIENT.getClientId(), PRINCIPAL, null, null, (Set<String>) null, null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("authorizationUri cannot be empty");
	}

	@Test
	public void constructorWhenClientIdNotProvidedThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationCodeRequestAuthenticationToken(AUTHORIZATION_URI, null,
				PRINCIPAL, null, null, (Set<String>) null, null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("clientId cannot be empty");
	}

	@Test
	public void constructorWhenPrincipalNotProvidedThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationCodeRequestAuthenticationToken(AUTHORIZATION_URI,
				REGISTERED_CLIENT.getClientId(), null, null, null, (Set<String>) null, null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("principal cannot be null");
	}

	@Test
	public void constructorWhenAuthorizationCodeNotProvidedThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationCodeRequestAuthenticationToken(AUTHORIZATION_URI,
				REGISTERED_CLIENT.getClientId(), PRINCIPAL, null, null, null, (Set<String>) null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("authorizationCode cannot be null");
	}

	@Test
	public void constructorWhenAuthorizationRequestThenValuesAreSet() {
		String clientId = REGISTERED_CLIENT.getClientId();
		String redirectUri = REGISTERED_CLIENT.getRedirectUris().iterator().next();
		String state = "state";
		Set<String> requestedScopes = REGISTERED_CLIENT.getScopes();
		Map<String, Object> additionalParameters = Collections.singletonMap("param1", "value1");

		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, clientId, PRINCIPAL, redirectUri, state, requestedScopes, additionalParameters);

		assertThat(authentication.getPrincipal()).isEqualTo(PRINCIPAL);
		assertThat(authentication.getCredentials()).isEqualTo("");
		assertThat(authentication.getAuthorities()).isEmpty();
		assertThat(authentication.getAuthorizationUri()).isEqualTo(AUTHORIZATION_URI);
		assertThat(authentication.getClientId()).isEqualTo(clientId);
		assertThat(authentication.getRedirectUri()).isEqualTo(redirectUri);
		assertThat(authentication.getState()).isEqualTo(state);
		assertThat(authentication.getScopes()).containsExactlyInAnyOrderElementsOf(requestedScopes);
		assertThat(authentication.getAdditionalParameters()).containsExactlyInAnyOrderEntriesOf(additionalParameters);
		assertThat(authentication.getAuthorizationCode()).isNull();
		assertThat(authentication.isAuthenticated()).isFalse();
	}

	@Test
	public void constructorWhenAuthorizationResponseThenValuesAreSet() {
		String clientId = REGISTERED_CLIENT.getClientId();
		String redirectUri = REGISTERED_CLIENT.getRedirectUris().iterator().next();
		String state = "state";
		Set<String> authorizedScopes = REGISTERED_CLIENT.getScopes();

		OAuth2AuthorizationCodeRequestAuthenticationToken authentication = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				AUTHORIZATION_URI, clientId, PRINCIPAL, AUTHORIZATION_CODE, redirectUri, state, authorizedScopes);

		assertThat(authentication.getPrincipal()).isEqualTo(PRINCIPAL);
		assertThat(authentication.getCredentials()).isEqualTo("");
		assertThat(authentication.getAuthorities()).isEmpty();
		assertThat(authentication.getAuthorizationUri()).isEqualTo(AUTHORIZATION_URI);
		assertThat(authentication.getClientId()).isEqualTo(clientId);
		assertThat(authentication.getRedirectUri()).isEqualTo(redirectUri);
		assertThat(authentication.getState()).isEqualTo(state);
		assertThat(authentication.getScopes()).containsExactlyInAnyOrderElementsOf(authorizedScopes);
		assertThat(authentication.getAdditionalParameters()).isEmpty();
		assertThat(authentication.getAuthorizationCode()).isEqualTo(AUTHORIZATION_CODE);
		assertThat(authentication.isAuthenticated()).isTrue();
	}

}
