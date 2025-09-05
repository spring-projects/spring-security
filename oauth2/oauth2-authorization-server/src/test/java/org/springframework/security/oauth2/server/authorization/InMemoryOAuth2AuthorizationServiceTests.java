/*
 * Copyright 2020-2023 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link InMemoryOAuth2AuthorizationService}.
 *
 * @author Krisztian Toth
 * @author Joe Grandja
 */
public class InMemoryOAuth2AuthorizationServiceTests {

	private static final String ID = "id";

	private static final RegisteredClient REGISTERED_CLIENT = TestRegisteredClients.registeredClient().build();

	private static final String PRINCIPAL_NAME = "principal";

	private static final AuthorizationGrantType AUTHORIZATION_GRANT_TYPE = AuthorizationGrantType.AUTHORIZATION_CODE;

	private static final OAuth2AuthorizationCode AUTHORIZATION_CODE = new OAuth2AuthorizationCode("code", Instant.now(),
			Instant.now().plus(5, ChronoUnit.MINUTES));

	private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.CODE);

	private static final OAuth2TokenType STATE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.STATE);

	private static final OAuth2TokenType ID_TOKEN_TOKEN_TYPE = new OAuth2TokenType(OidcParameterNames.ID_TOKEN);

	private InMemoryOAuth2AuthorizationService authorizationService;

	@BeforeEach
	public void setup() {
		this.authorizationService = new InMemoryOAuth2AuthorizationService();
	}

	@Test
	public void constructorVarargsWhenAuthorizationNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new InMemoryOAuth2AuthorizationService((OAuth2Authorization) null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("authorization cannot be null");
	}

	@Test
	public void constructorListWhenAuthorizationsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new InMemoryOAuth2AuthorizationService((List<OAuth2Authorization>) null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("authorizations cannot be null");
	}

	@Test
	public void constructorWhenDuplicateAuthorizationsThenThrowIllegalArgumentException() {
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
			.id(ID)
			.principalName(PRINCIPAL_NAME)
			.authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
			.token(AUTHORIZATION_CODE)
			.build();

		assertThatThrownBy(() -> new InMemoryOAuth2AuthorizationService(authorization, authorization))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("The authorization must be unique. Found duplicate identifier: id");
	}

	@Test
	public void saveWhenAuthorizationNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizationService.save(null)).isInstanceOf(IllegalArgumentException.class)
			.hasMessage("authorization cannot be null");
	}

	@Test
	public void saveWhenAuthorizationNewThenSaved() {
		OAuth2Authorization expectedAuthorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
			.id(ID)
			.principalName(PRINCIPAL_NAME)
			.authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
			.token(AUTHORIZATION_CODE)
			.build();
		this.authorizationService.save(expectedAuthorization);

		OAuth2Authorization authorization = this.authorizationService.findByToken(AUTHORIZATION_CODE.getTokenValue(),
				AUTHORIZATION_CODE_TOKEN_TYPE);
		assertThat(authorization).isEqualTo(expectedAuthorization);
	}

	// gh-222
	@Test
	public void saveWhenAuthorizationExistsThenUpdated() {
		OAuth2Authorization originalAuthorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
			.id(ID)
			.principalName(PRINCIPAL_NAME)
			.authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
			.token(AUTHORIZATION_CODE)
			.build();
		this.authorizationService.save(originalAuthorization);

		OAuth2Authorization authorization = this.authorizationService.findById(originalAuthorization.getId());
		assertThat(authorization).isEqualTo(originalAuthorization);

		OAuth2Authorization updatedAuthorization = OAuth2Authorization.from(authorization)
			.attribute("custom-name-1", "custom-value-1")
			.build();
		this.authorizationService.save(updatedAuthorization);

		authorization = this.authorizationService.findById(updatedAuthorization.getId());
		assertThat(authorization).isEqualTo(updatedAuthorization);
		assertThat(authorization).isNotEqualTo(originalAuthorization);
	}

	@Test
	public void saveWhenInitializedAuthorizationsReachMaxThenOldestRemoved() {
		int maxInitializedAuthorizations = 5;
		InMemoryOAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService(
				maxInitializedAuthorizations);

		OAuth2Authorization initialAuthorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
			.id(ID + "-initial")
			.principalName(PRINCIPAL_NAME)
			.authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
			.attribute(OAuth2ParameterNames.STATE, "state-initial")
			.build();
		authorizationService.save(initialAuthorization);

		OAuth2Authorization authorization = authorizationService.findById(initialAuthorization.getId());
		assertThat(authorization).isEqualTo(initialAuthorization);
		authorization = authorizationService.findByToken(initialAuthorization.getAttribute(OAuth2ParameterNames.STATE),
				STATE_TOKEN_TYPE);
		assertThat(authorization).isEqualTo(initialAuthorization);

		for (int i = 0; i < maxInitializedAuthorizations; i++) {
			authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
				.id(ID + "-" + i)
				.principalName(PRINCIPAL_NAME)
				.authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
				.attribute(OAuth2ParameterNames.STATE, "state-" + i)
				.build();
			authorizationService.save(authorization);
		}

		authorization = authorizationService.findById(initialAuthorization.getId());
		assertThat(authorization).isNull();
		authorization = authorizationService.findByToken(initialAuthorization.getAttribute(OAuth2ParameterNames.STATE),
				STATE_TOKEN_TYPE);
		assertThat(authorization).isNull();
	}

	@Test
	public void removeWhenAuthorizationNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizationService.remove(null)).isInstanceOf(IllegalArgumentException.class)
			.hasMessage("authorization cannot be null");
	}

	@Test
	public void removeWhenAuthorizationProvidedThenRemoved() {
		OAuth2Authorization expectedAuthorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
			.id(ID)
			.principalName(PRINCIPAL_NAME)
			.authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
			.token(AUTHORIZATION_CODE)
			.build();

		this.authorizationService.save(expectedAuthorization);
		OAuth2Authorization authorization = this.authorizationService.findByToken(AUTHORIZATION_CODE.getTokenValue(),
				AUTHORIZATION_CODE_TOKEN_TYPE);
		assertThat(authorization).isEqualTo(expectedAuthorization);

		this.authorizationService.remove(expectedAuthorization);
		authorization = this.authorizationService.findByToken(AUTHORIZATION_CODE.getTokenValue(),
				AUTHORIZATION_CODE_TOKEN_TYPE);
		assertThat(authorization).isNull();
	}

	@Test
	public void findByIdWhenIdNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizationService.findById(null)).isInstanceOf(IllegalArgumentException.class)
			.hasMessage("id cannot be empty");
	}

	@Test
	public void findByTokenWhenTokenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizationService.findByToken(null, AUTHORIZATION_CODE_TOKEN_TYPE))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("token cannot be empty");
	}

	@Test
	public void findByTokenWhenStateExistsThenFound() {
		String state = "state";
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
			.id(ID)
			.principalName(PRINCIPAL_NAME)
			.authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
			.attribute(OAuth2ParameterNames.STATE, state)
			.build();
		this.authorizationService.save(authorization);

		OAuth2Authorization result = this.authorizationService.findByToken(state, STATE_TOKEN_TYPE);
		assertThat(authorization).isEqualTo(result);
		result = this.authorizationService.findByToken(state, null);
		assertThat(authorization).isEqualTo(result);
	}

	@Test
	public void findByTokenWhenAuthorizationCodeExistsThenFound() {
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
			.id(ID)
			.principalName(PRINCIPAL_NAME)
			.authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
			.token(AUTHORIZATION_CODE)
			.build();
		this.authorizationService.save(authorization);

		OAuth2Authorization result = this.authorizationService.findByToken(AUTHORIZATION_CODE.getTokenValue(),
				AUTHORIZATION_CODE_TOKEN_TYPE);
		assertThat(authorization).isEqualTo(result);
		result = this.authorizationService.findByToken(AUTHORIZATION_CODE.getTokenValue(), null);
		assertThat(authorization).isEqualTo(result);
	}

	@Test
	public void findByTokenWhenAccessTokenExistsThenFound() {
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token",
				Instant.now().minusSeconds(60), Instant.now());
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
			.id(ID)
			.principalName(PRINCIPAL_NAME)
			.authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
			.token(AUTHORIZATION_CODE)
			.accessToken(accessToken)
			.build();
		this.authorizationService.save(authorization);

		OAuth2Authorization result = this.authorizationService.findByToken(accessToken.getTokenValue(),
				OAuth2TokenType.ACCESS_TOKEN);
		assertThat(authorization).isEqualTo(result);
		result = this.authorizationService.findByToken(accessToken.getTokenValue(), null);
		assertThat(authorization).isEqualTo(result);
	}

	@Test
	public void findByTokenWhenIdTokenExistsThenFound() {
		OidcIdToken idToken = OidcIdToken.withTokenValue("id-token")
			.issuer("https://provider.com")
			.subject("subject")
			.issuedAt(Instant.now().minusSeconds(60))
			.expiresAt(Instant.now())
			.build();
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
			.id(ID)
			.principalName(PRINCIPAL_NAME)
			.authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
			.token(idToken)
			.build();
		this.authorizationService.save(authorization);

		OAuth2Authorization result = this.authorizationService.findByToken(idToken.getTokenValue(),
				ID_TOKEN_TOKEN_TYPE);
		assertThat(authorization).isEqualTo(result);
		result = this.authorizationService.findByToken(idToken.getTokenValue(), null);
		assertThat(authorization).isEqualTo(result);
	}

	@Test
	public void findByTokenWhenRefreshTokenExistsThenFound() {
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", Instant.now());
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
			.id(ID)
			.principalName(PRINCIPAL_NAME)
			.authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
			.refreshToken(refreshToken)
			.build();
		this.authorizationService.save(authorization);

		OAuth2Authorization result = this.authorizationService.findByToken(refreshToken.getTokenValue(),
				OAuth2TokenType.REFRESH_TOKEN);
		assertThat(authorization).isEqualTo(result);
		result = this.authorizationService.findByToken(refreshToken.getTokenValue(), null);
		assertThat(authorization).isEqualTo(result);
	}

	@Test
	public void findByTokenWhenWrongTokenTypeThenNotFound() {
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", Instant.now());
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
			.id(ID)
			.principalName(PRINCIPAL_NAME)
			.authorizationGrantType(AUTHORIZATION_GRANT_TYPE)
			.refreshToken(refreshToken)
			.build();
		this.authorizationService.save(authorization);

		OAuth2Authorization result = this.authorizationService.findByToken(refreshToken.getTokenValue(),
				OAuth2TokenType.ACCESS_TOKEN);
		assertThat(result).isNull();
	}

	@Test
	public void findByTokenWhenTokenDoesNotExistThenNull() {
		OAuth2Authorization result = this.authorizationService.findByToken("access-token",
				OAuth2TokenType.ACCESS_TOKEN);
		assertThat(result).isNull();
	}

}
