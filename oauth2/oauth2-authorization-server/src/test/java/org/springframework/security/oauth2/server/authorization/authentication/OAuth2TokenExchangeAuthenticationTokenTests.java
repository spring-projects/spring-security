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
 * Tests for {@link OAuth2TokenExchangeAuthenticationToken}.
 *
 * @author Steve Riesenberg
 */
public class OAuth2TokenExchangeAuthenticationTokenTests {

	private static final Set<String> RESOURCES = Set.of("https://mydomain.com/resource1",
			"https://mydomain.com/resource2");

	private static final Set<String> AUDIENCES = Set.of("audience1", "audience2");

	private static final String SUBJECT_TOKEN = "EfYu_0jEL";

	private static final String ACTOR_TOKEN = "JlNE_xR1f";

	private static final String ACCESS_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:access_token";

	private static final String JWT_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:jwt";

	private RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();

	private OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(this.registeredClient,
			ClientAuthenticationMethod.CLIENT_SECRET_BASIC, this.registeredClient.getClientSecret());

	private Set<String> scopes = Collections.singleton("scope1");

	private Map<String, Object> additionalParameters = Collections.singletonMap("param1", "value1");

	@Test
	public void constructorWhenClientPrincipalNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatThrownBy(() -> new OAuth2TokenExchangeAuthenticationToken(null, null, null, null, null, null, null, null, null, this.additionalParameters))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("clientPrincipal cannot be null");
		// @formatter:on
	}

	@Test
	public void constructorWhenRequestedTokenTypeNullOrEmptyThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatThrownBy(() -> new OAuth2TokenExchangeAuthenticationToken(null, null, null, this.clientPrincipal, null, null, null, null, null, this.additionalParameters))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("requestedTokenType cannot be empty");
		assertThatThrownBy(() -> new OAuth2TokenExchangeAuthenticationToken("", null, null, this.clientPrincipal, null, null, null, null, null, this.additionalParameters))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("requestedTokenType cannot be empty");
		// @formatter:on
	}

	@Test
	public void constructorWhenSubjectTokenNullOrEmptyThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatThrownBy(() -> new OAuth2TokenExchangeAuthenticationToken(JWT_TOKEN_TYPE_VALUE, null, null, this.clientPrincipal, null, null, null, null, this.scopes, this.additionalParameters))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("subjectToken cannot be empty");
		assertThatThrownBy(() -> new OAuth2TokenExchangeAuthenticationToken(JWT_TOKEN_TYPE_VALUE, "", null, this.clientPrincipal, null, null, null, null, this.scopes, this.additionalParameters))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("subjectToken cannot be empty");
		// @formatter:on
	}

	@Test
	public void constructorWhenSubjectTokenTypeNullOrEmptyThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatThrownBy(() -> new OAuth2TokenExchangeAuthenticationToken(JWT_TOKEN_TYPE_VALUE, SUBJECT_TOKEN, null, this.clientPrincipal, null, null, null, null, this.scopes, this.additionalParameters))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("subjectTokenType cannot be empty");
		assertThatThrownBy(() -> new OAuth2TokenExchangeAuthenticationToken(JWT_TOKEN_TYPE_VALUE, SUBJECT_TOKEN, "", this.clientPrincipal, null, null, null, null, this.scopes, this.additionalParameters))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("subjectTokenType cannot be empty");
		// @formatter:on
	}

	@Test
	public void constructorWhenRequiredParametersProvidedThenCreated() {
		OAuth2TokenExchangeAuthenticationToken authentication = new OAuth2TokenExchangeAuthenticationToken(
				JWT_TOKEN_TYPE_VALUE, SUBJECT_TOKEN, ACCESS_TOKEN_TYPE_VALUE, this.clientPrincipal, null, null, null,
				null, null, this.additionalParameters);
		assertThat(authentication.getPrincipal()).isEqualTo(this.clientPrincipal);
		assertThat(authentication.getCredentials().toString()).isEmpty();
		assertThat(authentication.getGrantType()).isEqualTo(AuthorizationGrantType.TOKEN_EXCHANGE);
		assertThat(authentication.getRequestedTokenType()).isEqualTo(JWT_TOKEN_TYPE_VALUE);
		assertThat(authentication.getSubjectToken()).isEqualTo(SUBJECT_TOKEN);
		assertThat(authentication.getSubjectTokenType()).isEqualTo(ACCESS_TOKEN_TYPE_VALUE);
		assertThat(authentication.getActorToken()).isNull();
		assertThat(authentication.getActorTokenType()).isNull();
		assertThat(authentication.getResources()).isEmpty();
		assertThat(authentication.getAudiences()).isEmpty();
		assertThat(authentication.getScopes()).isEmpty();
		assertThat(authentication.getAdditionalParameters()).isEqualTo(this.additionalParameters);
	}

	@Test
	public void constructorWhenAllParametersProvidedThenCreated() {
		OAuth2TokenExchangeAuthenticationToken authentication = new OAuth2TokenExchangeAuthenticationToken(
				JWT_TOKEN_TYPE_VALUE, SUBJECT_TOKEN, ACCESS_TOKEN_TYPE_VALUE, this.clientPrincipal, ACTOR_TOKEN,
				ACCESS_TOKEN_TYPE_VALUE, RESOURCES, AUDIENCES, this.scopes, this.additionalParameters);
		assertThat(authentication.getPrincipal()).isEqualTo(this.clientPrincipal);
		assertThat(authentication.getCredentials().toString()).isEmpty();
		assertThat(authentication.getGrantType()).isEqualTo(AuthorizationGrantType.TOKEN_EXCHANGE);
		assertThat(authentication.getRequestedTokenType()).isEqualTo(JWT_TOKEN_TYPE_VALUE);
		assertThat(authentication.getSubjectToken()).isEqualTo(SUBJECT_TOKEN);
		assertThat(authentication.getSubjectTokenType()).isEqualTo(ACCESS_TOKEN_TYPE_VALUE);
		assertThat(authentication.getActorToken()).isEqualTo(ACTOR_TOKEN);
		assertThat(authentication.getActorTokenType()).isEqualTo(ACCESS_TOKEN_TYPE_VALUE);
		assertThat(authentication.getResources()).isEqualTo(RESOURCES);
		assertThat(authentication.getAudiences()).isEqualTo(AUDIENCES);
		assertThat(authentication.getScopes()).isEqualTo(this.scopes);
		assertThat(authentication.getAdditionalParameters()).isEqualTo(this.additionalParameters);
	}

}
