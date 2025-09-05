/*
 * Copyright 2020-2025 the original author or authors.
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

import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.context.TestAuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimNames;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests for {@link OAuth2TokenExchangeAuthenticationProvider}.
 *
 * @author Steve Riesenberg
 */
public class OAuth2TokenExchangeAuthenticationProviderTests {

	private static final Set<String> RESOURCES = Set.of("https://mydomain.com/resource1",
			"https://mydomain.com/resource2");

	private static final Set<String> AUDIENCES = Set.of("audience1", "audience2");

	private static final String SUBJECT_TOKEN = "EfYu_0jEL";

	private static final String ACTOR_TOKEN = "JlNE_xR1f";

	private static final String ACCESS_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:access_token";

	private static final String JWT_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:jwt";

	private OAuth2AuthorizationService authorizationService;

	private OAuth2TokenGenerator<OAuth2Token> tokenGenerator;

	private JwtEncoder dPoPProofJwtEncoder;

	private OAuth2TokenExchangeAuthenticationProvider authenticationProvider;

	@BeforeEach
	@SuppressWarnings("unchecked")
	public void setUp() {
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.tokenGenerator = mock(OAuth2TokenGenerator.class);
		JWKSet clientJwkSet = new JWKSet(TestJwks.DEFAULT_EC_JWK);
		JWKSource<SecurityContext> clientJwkSource = (jwkSelector, securityContext) -> jwkSelector.select(clientJwkSet);
		this.dPoPProofJwtEncoder = new NimbusJwtEncoder(clientJwkSource);
		this.authenticationProvider = new OAuth2TokenExchangeAuthenticationProvider(this.authorizationService,
				this.tokenGenerator);
		mockAuthorizationServerContext();
	}

	@AfterEach
	public void tearDown() {
		AuthorizationServerContextHolder.resetContext();
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2TokenExchangeAuthenticationProvider(null, this.tokenGenerator))
				.withMessage("authorizationService cannot be null");
		// @formatter:on
	}

	@Test
	public void constructorWhenTokenGeneratorNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2TokenExchangeAuthenticationProvider(this.authorizationService, null))
				.withMessage("tokenGenerator cannot be null");
		// @formatter:on
	}

	@Test
	public void supportsWhenTypeOAuth2TokenExchangeAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2TokenExchangeAuthenticationToken.class)).isTrue();
	}

	@Test
	public void authenticateWhenClientNotAuthenticatedThenThrowOAuth2AuthenticationException() {
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken("client-1",
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null, null);
		Authentication authentication = new OAuth2TokenExchangeAuthenticationToken(JWT_TOKEN_TYPE_VALUE, SUBJECT_TOKEN,
				ACCESS_TOKEN_TYPE_VALUE, clientPrincipal, null, null, RESOURCES, AUDIENCES, null, null);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
		// @formatter:on
	}

	@Test
	public void authenticateWhenInvalidGrantTypeThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2TokenExchangeAuthenticationToken authentication = createDelegationRequest(registeredClient);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
		// @formatter:on
	}

	@Test
	public void authenticateWhenInvalidRequestedTokenTypeThenThrowOAuth2AuthenticationException() {
		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
				.tokenSettings(TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.REFERENCE).build())
				.build();
		// @formatter:on
		OAuth2TokenExchangeAuthenticationToken authentication = createDelegationRequest(registeredClient);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on
	}

	@Test
	public void authenticateWhenSubjectTokenNotFoundThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
			.build();
		OAuth2TokenExchangeAuthenticationToken authentication = createDelegationRequest(registeredClient);
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(null);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
		// @formatter:on

		verify(this.authorizationService).findByToken(SUBJECT_TOKEN, OAuth2TokenType.ACCESS_TOKEN);
		verifyNoMoreInteractions(this.authorizationService);
		verifyNoInteractions(this.tokenGenerator);
	}

	@Test
	public void authenticateWhenSubjectTokenNotActiveThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
			.build();
		OAuth2TokenExchangeAuthenticationToken authentication = createDelegationRequest(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.token(createExpiredAccessToken(SUBJECT_TOKEN))
			.build();
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(authorization);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
		// @formatter:on

		verify(this.authorizationService).findByToken(SUBJECT_TOKEN, OAuth2TokenType.ACCESS_TOKEN);
		verifyNoMoreInteractions(this.authorizationService);
		verifyNoInteractions(this.tokenGenerator);
	}

	@Test
	public void authenticateWhenSubjectTokenTypeJwtAndSubjectTokenFormatReferenceThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
			.build();
		OAuth2TokenExchangeAuthenticationToken authentication = createJwtRequest(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.token(createAccessToken(SUBJECT_TOKEN), withTokenFormat(OAuth2TokenFormat.REFERENCE))
			.build();
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(authorization);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on

		verify(this.authorizationService).findByToken(SUBJECT_TOKEN, OAuth2TokenType.ACCESS_TOKEN);
		verifyNoMoreInteractions(this.authorizationService);
		verifyNoInteractions(this.tokenGenerator);
	}

	@Test
	public void authenticateWhenSubjectPrincipalNullThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
			.build();
		OAuth2TokenExchangeAuthenticationToken authentication = createDelegationRequest(registeredClient);
		// @formatter:off
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.token(createAccessToken(SUBJECT_TOKEN))
				.attributes((attributes) -> attributes.remove(Principal.class.getName()))
				.build();
		// @formatter:on
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(authorization);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
		// @formatter:on

		verify(this.authorizationService).findByToken(SUBJECT_TOKEN, OAuth2TokenType.ACCESS_TOKEN);
		verifyNoMoreInteractions(this.authorizationService);
		verifyNoInteractions(this.tokenGenerator);
	}

	@Test
	public void authenticateWhenActorTokenNotFoundThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
			.build();
		OAuth2TokenExchangeAuthenticationToken authentication = createDelegationRequest(registeredClient);
		OAuth2Authorization subjectAuthorization = TestOAuth2Authorizations.authorization(registeredClient)
			.token(createAccessToken(SUBJECT_TOKEN))
			.build();
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class)))
			.willReturn(subjectAuthorization, (OAuth2Authorization) null);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
		// @formatter:on

		verify(this.authorizationService).findByToken(SUBJECT_TOKEN, OAuth2TokenType.ACCESS_TOKEN);
		verify(this.authorizationService).findByToken(ACTOR_TOKEN, OAuth2TokenType.ACCESS_TOKEN);
		verifyNoMoreInteractions(this.authorizationService);
		verifyNoInteractions(this.tokenGenerator);
	}

	@Test
	public void authenticateWhenActorTokenNotActiveThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
			.build();
		OAuth2TokenExchangeAuthenticationToken authentication = createDelegationRequest(registeredClient);
		OAuth2Authorization subjectAuthorization = TestOAuth2Authorizations.authorization(registeredClient)
			.token(createAccessToken(SUBJECT_TOKEN))
			.build();
		OAuth2Authorization actorAuthorization = TestOAuth2Authorizations.authorization(registeredClient)
			.token(createExpiredAccessToken(ACTOR_TOKEN))
			.build();
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class)))
			.willReturn(subjectAuthorization, actorAuthorization);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
		// @formatter:on

		verify(this.authorizationService).findByToken(SUBJECT_TOKEN, OAuth2TokenType.ACCESS_TOKEN);
		verify(this.authorizationService).findByToken(ACTOR_TOKEN, OAuth2TokenType.ACCESS_TOKEN);
		verifyNoMoreInteractions(this.authorizationService);
		verifyNoInteractions(this.tokenGenerator);
	}

	@Test
	public void authenticateWhenActorTokenTypeJwtAndActorTokenFormatReferenceThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
			.build();
		OAuth2TokenExchangeAuthenticationToken authentication = createJwtRequest(registeredClient);
		OAuth2Authorization subjectAuthorization = TestOAuth2Authorizations.authorization(registeredClient)
			.token(createAccessToken(SUBJECT_TOKEN), withTokenFormat(OAuth2TokenFormat.SELF_CONTAINED))
			.build();
		OAuth2Authorization actorAuthorization = TestOAuth2Authorizations.authorization(registeredClient)
			.token(createAccessToken(ACTOR_TOKEN), withTokenFormat(OAuth2TokenFormat.REFERENCE))
			.build();
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class)))
			.willReturn(subjectAuthorization, actorAuthorization);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_REQUEST);
		// @formatter:on

		verify(this.authorizationService).findByToken(SUBJECT_TOKEN, OAuth2TokenType.ACCESS_TOKEN);
		verify(this.authorizationService).findByToken(ACTOR_TOKEN, OAuth2TokenType.ACCESS_TOKEN);
		verifyNoMoreInteractions(this.authorizationService);
		verifyNoInteractions(this.tokenGenerator);
	}

	@Test
	public void authenticateWhenMayActAndActorIssClaimNotAuthorizedThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
			.build();
		OAuth2TokenExchangeAuthenticationToken authentication = createDelegationRequest(registeredClient);
		Map<String, String> authorizedActorClaims = Map.of(OAuth2TokenClaimNames.ISS, "issuer",
				OAuth2TokenClaimNames.SUB, "actor");
		// @formatter:off
		OAuth2Authorization subjectAuthorization = TestOAuth2Authorizations.authorization(registeredClient)
				.token(createAccessToken(SUBJECT_TOKEN), withClaims(Map.of("may_act", authorizedActorClaims)))
				.build();
		// @formatter:on
		Map<String, Object> actorTokenClaims = Map.of(OAuth2TokenClaimNames.ISS, "invalid-issuer",
				OAuth2TokenClaimNames.SUB, "actor");
		OAuth2Authorization actorAuthorization = TestOAuth2Authorizations.authorization(registeredClient)
			.token(createAccessToken(ACTOR_TOKEN), withClaims(actorTokenClaims))
			.build();
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class)))
			.willReturn(subjectAuthorization, actorAuthorization);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
		// @formatter:on

		verify(this.authorizationService).findByToken(SUBJECT_TOKEN, OAuth2TokenType.ACCESS_TOKEN);
		verify(this.authorizationService).findByToken(ACTOR_TOKEN, OAuth2TokenType.ACCESS_TOKEN);
		verifyNoMoreInteractions(this.authorizationService);
		verifyNoInteractions(this.tokenGenerator);
	}

	@Test
	public void authenticateWhenMayActAndActorSubClaimNotAuthorizedThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
			.build();
		OAuth2TokenExchangeAuthenticationToken authentication = createDelegationRequest(registeredClient);
		Map<String, String> authorizedActorClaims = Map.of(OAuth2TokenClaimNames.ISS, "issuer",
				OAuth2TokenClaimNames.SUB, "actor");
		// @formatter:off
		OAuth2Authorization subjectAuthorization = TestOAuth2Authorizations.authorization(registeredClient)
				.token(createAccessToken(SUBJECT_TOKEN), withClaims(Map.of("may_act", authorizedActorClaims)))
				.build();
		// @formatter:on
		Map<String, Object> actorTokenClaims = Map.of(OAuth2TokenClaimNames.ISS, "issuer", OAuth2TokenClaimNames.SUB,
				"invalid-actor");
		OAuth2Authorization actorAuthorization = TestOAuth2Authorizations.authorization(registeredClient)
			.token(createAccessToken(ACTOR_TOKEN), withClaims(actorTokenClaims))
			.build();
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class)))
			.willReturn(subjectAuthorization, actorAuthorization);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
		// @formatter:on

		verify(this.authorizationService).findByToken(SUBJECT_TOKEN, OAuth2TokenType.ACCESS_TOKEN);
		verify(this.authorizationService).findByToken(ACTOR_TOKEN, OAuth2TokenType.ACCESS_TOKEN);
		verifyNoMoreInteractions(this.authorizationService);
		verifyNoInteractions(this.tokenGenerator);
	}

	@Test
	public void authenticateWhenMayActAndImpersonationThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
			.build();
		OAuth2TokenExchangeAuthenticationToken authentication = createImpersonationRequest(registeredClient);
		Map<String, String> authorizedActorClaims = Map.of(OAuth2TokenClaimNames.ISS, "issuer",
				OAuth2TokenClaimNames.SUB, "actor");
		// @formatter:off
		OAuth2Authorization subjectAuthorization = TestOAuth2Authorizations.authorization(registeredClient)
				.token(createAccessToken(SUBJECT_TOKEN), withClaims(Map.of("may_act", authorizedActorClaims)))
				.build();
		// @formatter:on
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class)))
			.willReturn(subjectAuthorization);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
		// @formatter:on

		verify(this.authorizationService).findByToken(SUBJECT_TOKEN, OAuth2TokenType.ACCESS_TOKEN);
		verifyNoMoreInteractions(this.authorizationService);
		verifyNoInteractions(this.tokenGenerator);
	}

	@Test
	public void authenticateWhenInvalidScopeInRequestThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
			.build();
		OAuth2TokenExchangeAuthenticationToken authentication = createDelegationRequest(registeredClient,
				Set.of("invalid"));
		OAuth2Authorization subjectAuthorization = TestOAuth2Authorizations.authorization(registeredClient)
			.token(createAccessToken(SUBJECT_TOKEN))
			.build();
		OAuth2Authorization actorAuthorization = TestOAuth2Authorizations.authorization(registeredClient)
			.token(createAccessToken(ACTOR_TOKEN))
			.build();
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class)))
			.willReturn(subjectAuthorization, actorAuthorization);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE);
		// @formatter:on

		verify(this.authorizationService).findByToken(SUBJECT_TOKEN, OAuth2TokenType.ACCESS_TOKEN);
		verify(this.authorizationService).findByToken(ACTOR_TOKEN, OAuth2TokenType.ACCESS_TOKEN);
		verifyNoMoreInteractions(this.authorizationService);
		verifyNoInteractions(this.tokenGenerator);
	}

	@Test
	public void authenticateWhenInvalidScopeInSubjectAuthorizationThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
			.build();
		OAuth2TokenExchangeAuthenticationToken authentication = createDelegationRequest(registeredClient, Set.of());
		OAuth2Authorization subjectAuthorization = TestOAuth2Authorizations.authorization(registeredClient)
			.token(createAccessToken(SUBJECT_TOKEN))
			.authorizedScopes(Set.of("invalid"))
			.build();
		OAuth2Authorization actorAuthorization = TestOAuth2Authorizations.authorization(registeredClient)
			.token(createAccessToken(ACTOR_TOKEN))
			.build();
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class)))
			.willReturn(subjectAuthorization, actorAuthorization);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE);
		// @formatter:on

		verify(this.authorizationService).findByToken(SUBJECT_TOKEN, OAuth2TokenType.ACCESS_TOKEN);
		verify(this.authorizationService).findByToken(ACTOR_TOKEN, OAuth2TokenType.ACCESS_TOKEN);
		verifyNoMoreInteractions(this.authorizationService);
		verifyNoInteractions(this.tokenGenerator);
	}

	@Test
	public void authenticateWhenNoActorTokenAndValidTokenExchangeThenReturnAccessTokenForImpersonation() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
			.build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null);
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put("dpop_proof", generateDPoPProof("http://localhost/oauth2/token"));
		additionalParameters.put("dpop_method", "POST");
		additionalParameters.put("dpop_target_uri", "http://localhost/oauth2/token");
		OAuth2TokenExchangeAuthenticationToken authentication = new OAuth2TokenExchangeAuthenticationToken(
				JWT_TOKEN_TYPE_VALUE, SUBJECT_TOKEN, ACCESS_TOKEN_TYPE_VALUE, clientPrincipal, null, null, RESOURCES,
				AUDIENCES, registeredClient.getScopes(), additionalParameters);
		TestingAuthenticationToken userPrincipal = new TestingAuthenticationToken("user", null, "ROLE_USER");
		// @formatter:off
		OAuth2Authorization subjectAuthorization = TestOAuth2Authorizations.authorization(registeredClient)
				.token(createAccessToken(SUBJECT_TOKEN))
				.attribute(Principal.class.getName(), userPrincipal)
				.build();
		// @formatter:on
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class)))
			.willReturn(subjectAuthorization);
		OAuth2AccessToken accessToken = createAccessToken("token-value");
		given(this.tokenGenerator.generate(any(OAuth2TokenContext.class))).willReturn(accessToken);
		OAuth2AccessTokenAuthenticationToken authenticationResult = (OAuth2AccessTokenAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);
		assertThat(authenticationResult.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(authenticationResult.getPrincipal()).isEqualTo(authentication.getPrincipal());
		assertThat(authenticationResult.getAccessToken()).isEqualTo(accessToken);
		assertThat(authenticationResult.getRefreshToken()).isNull();
		assertThat(authenticationResult.getAdditionalParameters()).hasSize(1);
		assertThat(authenticationResult.getAdditionalParameters().get(OAuth2ParameterNames.ISSUED_TOKEN_TYPE))
			.isEqualTo(JWT_TOKEN_TYPE_VALUE);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		ArgumentCaptor<OAuth2TokenContext> tokenContextCaptor = ArgumentCaptor.forClass(OAuth2TokenContext.class);
		verify(this.authorizationService).findByToken(SUBJECT_TOKEN, OAuth2TokenType.ACCESS_TOKEN);
		verify(this.tokenGenerator).generate(tokenContextCaptor.capture());
		verify(this.authorizationService).save(authorizationCaptor.capture());
		verifyNoMoreInteractions(this.authorizationService, this.tokenGenerator);

		OAuth2TokenContext tokenContext = tokenContextCaptor.getValue();
		assertThat(tokenContext.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(tokenContext.getAuthorization()).isEqualTo(subjectAuthorization);
		assertThat(tokenContext.<Authentication>getPrincipal()).isSameAs(userPrincipal);
		assertThat(tokenContext.getAuthorizationServerContext()).isNotNull();
		assertThat(tokenContext.getAuthorizedScopes()).isEqualTo(authentication.getScopes());
		assertThat(tokenContext.getTokenType()).isEqualTo(OAuth2TokenType.ACCESS_TOKEN);
		assertThat(tokenContext.<Authentication>getAuthorizationGrant()).isEqualTo(authentication);
		assertThat(tokenContext.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.TOKEN_EXCHANGE);
		assertThat(tokenContext.<Jwt>get(OAuth2TokenContext.DPOP_PROOF_KEY)).isNotNull();

		OAuth2Authorization authorization = authorizationCaptor.getValue();
		assertThat(authorization.getPrincipalName()).isEqualTo(subjectAuthorization.getPrincipalName());
		assertThat(authorization.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.TOKEN_EXCHANGE);
		assertThat(authorization.getAuthorizedScopes()).isEqualTo(authentication.getScopes());
		assertThat(authorization.<Authentication>getAttribute(Principal.class.getName())).isSameAs(userPrincipal);
		assertThat(authorization.getAccessToken().getToken()).isEqualTo(accessToken);
		assertThat(authorization.getRefreshToken()).isNull();
	}

	@Test
	public void authenticateWhenNoActorTokenAndPreviousActorThenReturnAccessTokenForImpersonation() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
			.build();
		OAuth2TokenExchangeAuthenticationToken authentication = createImpersonationRequest(registeredClient);
		TestingAuthenticationToken userPrincipal = new TestingAuthenticationToken("user", null, "ROLE_USER");
		OAuth2TokenExchangeActor previousActor = new OAuth2TokenExchangeActor(
				Map.of(OAuth2TokenClaimNames.ISS, "issuer1", OAuth2TokenClaimNames.SUB, "actor"));
		OAuth2TokenExchangeCompositeAuthenticationToken subjectPrincipal = new OAuth2TokenExchangeCompositeAuthenticationToken(
				userPrincipal, List.of(previousActor));
		// @formatter:off
		OAuth2Authorization subjectAuthorization = TestOAuth2Authorizations.authorization(registeredClient)
				.token(createAccessToken(SUBJECT_TOKEN))
				.attribute(Principal.class.getName(), subjectPrincipal)
				.build();
		// @formatter:on
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class)))
			.willReturn(subjectAuthorization);
		OAuth2AccessToken accessToken = createAccessToken("token-value");
		given(this.tokenGenerator.generate(any(OAuth2TokenContext.class))).willReturn(accessToken);
		OAuth2AccessTokenAuthenticationToken authenticationResult = (OAuth2AccessTokenAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);
		assertThat(authenticationResult.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(authenticationResult.getPrincipal()).isEqualTo(authentication.getPrincipal());
		assertThat(authenticationResult.getAccessToken()).isEqualTo(accessToken);
		assertThat(authenticationResult.getRefreshToken()).isNull();
		assertThat(authenticationResult.getAdditionalParameters()).hasSize(1);
		assertThat(authenticationResult.getAdditionalParameters().get(OAuth2ParameterNames.ISSUED_TOKEN_TYPE))
			.isEqualTo(JWT_TOKEN_TYPE_VALUE);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		ArgumentCaptor<OAuth2TokenContext> tokenContextCaptor = ArgumentCaptor.forClass(OAuth2TokenContext.class);
		verify(this.authorizationService).findByToken(SUBJECT_TOKEN, OAuth2TokenType.ACCESS_TOKEN);
		verify(this.tokenGenerator).generate(tokenContextCaptor.capture());
		verify(this.authorizationService).save(authorizationCaptor.capture());
		verifyNoMoreInteractions(this.authorizationService, this.tokenGenerator);

		OAuth2TokenContext tokenContext = tokenContextCaptor.getValue();
		assertThat(tokenContext.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(tokenContext.getAuthorization()).isEqualTo(subjectAuthorization);
		assertThat(tokenContext.<Authentication>getPrincipal()).isSameAs(userPrincipal);
		assertThat(tokenContext.getAuthorizationServerContext()).isNotNull();
		assertThat(tokenContext.getAuthorizedScopes()).isEqualTo(authentication.getScopes());
		assertThat(tokenContext.getTokenType()).isEqualTo(OAuth2TokenType.ACCESS_TOKEN);
		assertThat(tokenContext.<Authentication>getAuthorizationGrant()).isEqualTo(authentication);
		assertThat(tokenContext.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.TOKEN_EXCHANGE);

		OAuth2Authorization authorization = authorizationCaptor.getValue();
		assertThat(authorization.getPrincipalName()).isEqualTo(subjectAuthorization.getPrincipalName());
		assertThat(authorization.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.TOKEN_EXCHANGE);
		assertThat(authorization.getAuthorizedScopes()).isEqualTo(authentication.getScopes());
		assertThat(authorization.<Authentication>getAttribute(Principal.class.getName())).isSameAs(userPrincipal);
		assertThat(authorization.getAccessToken().getToken()).isEqualTo(accessToken);
		assertThat(authorization.getRefreshToken()).isNull();
	}

	@Test
	public void authenticateWhenActorTokenAndValidTokenExchangeThenReturnAccessTokenForDelegation() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
			.build();
		OAuth2TokenExchangeAuthenticationToken authentication = createDelegationRequest(registeredClient);
		TestingAuthenticationToken userPrincipal = new TestingAuthenticationToken("user", null, "ROLE_USER");
		OAuth2TokenExchangeActor actor1 = new OAuth2TokenExchangeActor(
				Map.of(OAuth2TokenClaimNames.ISS, "issuer1", OAuth2TokenClaimNames.SUB, "actor1"));
		OAuth2TokenExchangeActor actor2 = new OAuth2TokenExchangeActor(
				Map.of(OAuth2TokenClaimNames.ISS, "issuer2", OAuth2TokenClaimNames.SUB, "actor2"));
		OAuth2TokenExchangeCompositeAuthenticationToken subjectPrincipal = new OAuth2TokenExchangeCompositeAuthenticationToken(
				userPrincipal, List.of(actor1));
		// @formatter:off
		OAuth2Authorization subjectAuthorization = TestOAuth2Authorizations.authorization(registeredClient)
				.token(createAccessToken(SUBJECT_TOKEN), withClaims(Map.of("may_act", actor2.getClaims())))
				.attribute(Principal.class.getName(), subjectPrincipal)
				.build();
		OAuth2Authorization actorAuthorization = TestOAuth2Authorizations.authorization(registeredClient)
				.principalName(actor2.getSubject())
				.token(createAccessToken(ACTOR_TOKEN), withClaims(actor2.getClaims()))
				.build();
		// @formatter:on
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class)))
			.willReturn(subjectAuthorization, actorAuthorization);
		OAuth2AccessToken accessToken = createAccessToken("token-value");
		given(this.tokenGenerator.generate(any(OAuth2TokenContext.class))).willReturn(accessToken);
		OAuth2AccessTokenAuthenticationToken authenticationResult = (OAuth2AccessTokenAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);
		assertThat(authenticationResult.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(authenticationResult.getPrincipal()).isEqualTo(authentication.getPrincipal());
		assertThat(authenticationResult.getAccessToken()).isEqualTo(accessToken);
		assertThat(authenticationResult.getRefreshToken()).isNull();
		assertThat(authenticationResult.getAdditionalParameters()).hasSize(1);
		assertThat(authenticationResult.getAdditionalParameters().get(OAuth2ParameterNames.ISSUED_TOKEN_TYPE))
			.isEqualTo(JWT_TOKEN_TYPE_VALUE);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		ArgumentCaptor<OAuth2TokenContext> tokenContextCaptor = ArgumentCaptor.forClass(OAuth2TokenContext.class);
		verify(this.authorizationService).findByToken(SUBJECT_TOKEN, OAuth2TokenType.ACCESS_TOKEN);
		verify(this.authorizationService).findByToken(ACTOR_TOKEN, OAuth2TokenType.ACCESS_TOKEN);
		verify(this.tokenGenerator).generate(tokenContextCaptor.capture());
		verify(this.authorizationService).save(authorizationCaptor.capture());
		verifyNoMoreInteractions(this.authorizationService, this.tokenGenerator);

		OAuth2TokenContext tokenContext = tokenContextCaptor.getValue();
		assertThat(tokenContext.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(tokenContext.getAuthorization()).isEqualTo(subjectAuthorization);
		assertThat(tokenContext.getAuthorizationServerContext()).isNotNull();
		assertThat(tokenContext.getAuthorizedScopes()).isEqualTo(authentication.getScopes());
		assertThat(tokenContext.getTokenType()).isEqualTo(OAuth2TokenType.ACCESS_TOKEN);
		assertThat(tokenContext.<Authentication>getAuthorizationGrant()).isEqualTo(authentication);
		assertThat(tokenContext.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.TOKEN_EXCHANGE);

		OAuth2TokenExchangeCompositeAuthenticationToken tokenContextPrincipal = tokenContext.getPrincipal();
		assertThat(tokenContextPrincipal.getSubject()).isSameAs(subjectPrincipal.getSubject());
		assertThat(tokenContextPrincipal.getActors()).containsExactly(actor2, actor1);

		OAuth2Authorization authorization = authorizationCaptor.getValue();
		assertThat(authorization.getPrincipalName()).isEqualTo(subjectAuthorization.getPrincipalName());
		assertThat(authorization.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.TOKEN_EXCHANGE);
		assertThat(authorization.getAuthorizedScopes()).isEqualTo(authentication.getScopes());
		assertThat(authorization.getAccessToken().getToken()).isEqualTo(accessToken);
		assertThat(authorization.getRefreshToken()).isNull();

		OAuth2TokenExchangeCompositeAuthenticationToken authorizationPrincipal = authorization
			.getAttribute(Principal.class.getName());
		assertThat(authorizationPrincipal).isNotNull();
		assertThat(authorizationPrincipal.getSubject()).isSameAs(subjectPrincipal.getSubject());
		assertThat(authorizationPrincipal.getActors()).containsExactly(actor2, actor1);
	}

	private static void mockAuthorizationServerContext() {
		AuthorizationServerSettings authorizationServerSettings = AuthorizationServerSettings.builder().build();
		TestAuthorizationServerContext authorizationServerContext = new TestAuthorizationServerContext(
				authorizationServerSettings, () -> "https://provider.com");
		AuthorizationServerContextHolder.setContext(authorizationServerContext);
	}

	private static OAuth2TokenExchangeAuthenticationToken createDelegationRequest(RegisteredClient registeredClient) {
		return createDelegationRequest(registeredClient, registeredClient.getScopes());
	}

	private static OAuth2TokenExchangeAuthenticationToken createDelegationRequest(RegisteredClient registeredClient,
			Set<String> requestedScopes) {
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null);
		return new OAuth2TokenExchangeAuthenticationToken(JWT_TOKEN_TYPE_VALUE, SUBJECT_TOKEN, ACCESS_TOKEN_TYPE_VALUE,
				clientPrincipal, ACTOR_TOKEN, ACCESS_TOKEN_TYPE_VALUE, RESOURCES, AUDIENCES, requestedScopes, null);
	}

	private static OAuth2TokenExchangeAuthenticationToken createImpersonationRequest(
			RegisteredClient registeredClient) {
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null);
		return new OAuth2TokenExchangeAuthenticationToken(JWT_TOKEN_TYPE_VALUE, SUBJECT_TOKEN, ACCESS_TOKEN_TYPE_VALUE,
				clientPrincipal, null, null, RESOURCES, AUDIENCES, registeredClient.getScopes(), null);
	}

	private static OAuth2TokenExchangeAuthenticationToken createJwtRequest(RegisteredClient registeredClient) {
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null);
		return new OAuth2TokenExchangeAuthenticationToken(JWT_TOKEN_TYPE_VALUE, SUBJECT_TOKEN, JWT_TOKEN_TYPE_VALUE,
				clientPrincipal, ACTOR_TOKEN, JWT_TOKEN_TYPE_VALUE, RESOURCES, AUDIENCES, registeredClient.getScopes(),
				null);
	}

	private static OAuth2AccessToken createAccessToken(String tokenValue) {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(30, ChronoUnit.MINUTES);
		return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, tokenValue, issuedAt, expiresAt);
	}

	private static OAuth2AccessToken createExpiredAccessToken(String tokenValue) {
		Instant issuedAt = Instant.now().minus(45, ChronoUnit.MINUTES);
		Instant expiresAt = issuedAt.plus(30, ChronoUnit.MINUTES);
		return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, tokenValue, issuedAt, expiresAt);
	}

	private static Consumer<Map<String, Object>> withClaims(Map<String, Object> claims) {
		return (metadata) -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claims);
	}

	private static Consumer<Map<String, Object>> withTokenFormat(OAuth2TokenFormat tokenFormat) {
		return (metadata) -> metadata.put(OAuth2TokenFormat.class.getName(), tokenFormat.getValue());
	}

	private String generateDPoPProof(String tokenEndpointUri) {
		// @formatter:off
		Map<String, Object> publicJwk = TestJwks.DEFAULT_EC_JWK
				.toPublicJWK()
				.toJSONObject();
		JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.ES256)
				.type("dpop+jwt")
				.jwk(publicJwk)
				.build();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuedAt(Instant.now())
				.claim("htm", "POST")
				.claim("htu", tokenEndpointUri)
				.id(UUID.randomUUID().toString())
				.build();
		// @formatter:on
		Jwt jwt = this.dPoPProofJwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));
		return jwt.getTokenValue();
	}

}
