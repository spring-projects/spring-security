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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JoseHeaderNames;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
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
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.entry;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link OAuth2AuthorizationCodeAuthenticationProvider}.
 *
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 */
public class OAuth2AuthorizationCodeAuthenticationProviderTests {

	private static final String AUTHORIZATION_CODE = "code";

	private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.CODE);

	private OAuth2AuthorizationService authorizationService;

	private JwtEncoder jwtEncoder;

	private OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer;

	private OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer;

	private OAuth2TokenGenerator<?> tokenGenerator;

	private JwtEncoder dPoPProofJwtEncoder;

	private SessionRegistry sessionRegistry;

	private OAuth2AuthorizationCodeAuthenticationProvider authenticationProvider;

	@BeforeEach
	public void setUp() {
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.jwtEncoder = mock(JwtEncoder.class);
		this.jwtCustomizer = mock(OAuth2TokenCustomizer.class);
		JwtGenerator jwtGenerator = new JwtGenerator(this.jwtEncoder);
		jwtGenerator.setJwtCustomizer(this.jwtCustomizer);
		this.accessTokenCustomizer = mock(OAuth2TokenCustomizer.class);
		OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
		accessTokenGenerator.setAccessTokenCustomizer(this.accessTokenCustomizer);
		OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
		OAuth2TokenGenerator<OAuth2Token> delegatingTokenGenerator = new DelegatingOAuth2TokenGenerator(jwtGenerator,
				accessTokenGenerator, refreshTokenGenerator);
		this.tokenGenerator = spy(new OAuth2TokenGenerator<OAuth2Token>() {
			@Override
			public OAuth2Token generate(OAuth2TokenContext context) {
				return delegatingTokenGenerator.generate(context);
			}
		});
		JWKSet clientJwkSet = new JWKSet(TestJwks.DEFAULT_EC_JWK);
		JWKSource<SecurityContext> clientJwkSource = (jwkSelector, securityContext) -> jwkSelector.select(clientJwkSet);
		this.dPoPProofJwtEncoder = new NimbusJwtEncoder(clientJwkSource);
		this.sessionRegistry = mock(SessionRegistry.class);
		this.authenticationProvider = new OAuth2AuthorizationCodeAuthenticationProvider(this.authorizationService,
				this.tokenGenerator);
		this.authenticationProvider.setSessionRegistry(this.sessionRegistry);
		AuthorizationServerSettings authorizationServerSettings = AuthorizationServerSettings.builder()
			.issuer("https://provider.com")
			.build();
		AuthorizationServerContextHolder
			.setContext(new TestAuthorizationServerContext(authorizationServerSettings, null));
	}

	@AfterEach
	public void cleanup() {
		AuthorizationServerContextHolder.resetContext();
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationCodeAuthenticationProvider(null, this.tokenGenerator))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("authorizationService cannot be null");
	}

	@Test
	public void constructorWhenTokenGeneratorNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2AuthorizationCodeAuthenticationProvider(this.authorizationService, null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("tokenGenerator cannot be null");
	}

	@Test
	public void supportsWhenTypeOAuth2AuthorizationCodeAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2AuthorizationCodeAuthenticationToken.class)).isTrue();
	}

	@Test
	public void setSessionRegistryWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authenticationProvider.setSessionRegistry(null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("sessionRegistry cannot be null");
	}

	@Test
	public void authenticateWhenClientPrincipalNotOAuth2ClientAuthenticationTokenThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		TestingAuthenticationToken clientPrincipal = new TestingAuthenticationToken(registeredClient.getClientId(),
				registeredClient.getClientSecret());
		OAuth2AuthorizationCodeAuthenticationToken authentication = new OAuth2AuthorizationCodeAuthenticationToken(
				AUTHORIZATION_CODE, clientPrincipal, null, null);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenClientPrincipalNotAuthenticatedThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
				registeredClient.getClientId(), ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
				registeredClient.getClientSecret(), null);
		OAuth2AuthorizationCodeAuthenticationToken authentication = new OAuth2AuthorizationCodeAuthenticationToken(
				AUTHORIZATION_CODE, clientPrincipal, null, null);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenInvalidCodeThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2AuthorizationCodeAuthenticationToken authentication = new OAuth2AuthorizationCodeAuthenticationToken(
				AUTHORIZATION_CODE, clientPrincipal, null, null);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}

	@Test
	public void authenticateWhenCodeIssuedToAnotherClientThenThrowOAuth2AuthenticationException() {
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization().build();
		given(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
			.willReturn(authorization);

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2AuthorizationCodeAuthenticationToken authentication = new OAuth2AuthorizationCodeAuthenticationToken(
				AUTHORIZATION_CODE, clientPrincipal, null, null);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();
		OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = updatedAuthorization
			.getToken(OAuth2AuthorizationCode.class);
		assertThat(authorizationCode.isInvalidated()).isTrue();
	}

	@Test
	public void authenticateWhenInvalidRedirectUriThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		given(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
			.willReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		OAuth2AuthorizationCodeAuthenticationToken authentication = new OAuth2AuthorizationCodeAuthenticationToken(
				AUTHORIZATION_CODE, clientPrincipal, authorizationRequest.getRedirectUri() + "-invalid", null);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}

	@Test
	public void authenticateWhenInvalidatedCodeThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(AUTHORIZATION_CODE, Instant.now(),
				Instant.now().plusSeconds(120));
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.token(authorizationCode,
					(metadata) -> metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true))
			.build();
		given(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
			.willReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		OAuth2AuthorizationCodeAuthenticationToken authentication = new OAuth2AuthorizationCodeAuthenticationToken(
				AUTHORIZATION_CODE, clientPrincipal, authorizationRequest.getRedirectUri(), null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();
		assertThat(updatedAuthorization.getAccessToken().isInvalidated()).isTrue();
		assertThat(updatedAuthorization.getRefreshToken().isInvalidated()).isTrue();
	}

	// gh-1233
	@Test
	public void authenticateWhenInvalidatedCodeAndAccessTokenNullThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(AUTHORIZATION_CODE, Instant.now(),
				Instant.now().plusSeconds(120));
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient, authorizationCode)
			.token(authorizationCode,
					(metadata) -> metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true))
			.build();
		given(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
			.willReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		OAuth2AuthorizationCodeAuthenticationToken authentication = new OAuth2AuthorizationCodeAuthenticationToken(
				AUTHORIZATION_CODE, clientPrincipal, authorizationRequest.getRedirectUri(), null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);

		verify(this.authorizationService, never()).save(any());
	}

	// gh-290
	@Test
	public void authenticateWhenExpiredCodeThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(AUTHORIZATION_CODE,
				Instant.now().minusSeconds(300), Instant.now().minusSeconds(60));
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.token(authorizationCode)
			.build();
		given(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
			.willReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		OAuth2AuthorizationCodeAuthenticationToken authentication = new OAuth2AuthorizationCodeAuthenticationToken(
				AUTHORIZATION_CODE, clientPrincipal, authorizationRequest.getRedirectUri(), null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}

	@Test
	public void authenticateWhenAccessTokenNotGeneratedThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		given(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
			.willReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		OAuth2AuthorizationCodeAuthenticationToken authentication = new OAuth2AuthorizationCodeAuthenticationToken(
				AUTHORIZATION_CODE, clientPrincipal, authorizationRequest.getRedirectUri(), null);

		willAnswer((answer) -> {
			OAuth2TokenContext context = answer.getArgument(0);
			if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
				return null;
			}
			else {
				return answer.callRealMethod();
			}
		}).given(this.tokenGenerator).generate(any());

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.SERVER_ERROR);
				assertThat(error.getDescription()).contains("The token generator failed to generate the access token.");
			});
	}

	@Test
	public void authenticateWhenInvalidRefreshTokenGeneratedThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		given(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
			.willReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		OAuth2AuthorizationCodeAuthenticationToken authentication = new OAuth2AuthorizationCodeAuthenticationToken(
				AUTHORIZATION_CODE, clientPrincipal, authorizationRequest.getRedirectUri(), null);

		given(this.jwtEncoder.encode(any())).willReturn(createJwt());

		willAnswer((answer) -> {
			OAuth2TokenContext context = answer.getArgument(0);
			if (OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
				return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token", Instant.now(),
						Instant.now().plusSeconds(300));
			}
			else {
				return answer.callRealMethod();
			}
		}).given(this.tokenGenerator).generate(any());

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.SERVER_ERROR);
				assertThat(error.getDescription())
					.contains("The token generator failed to generate a valid refresh token.");
			});
	}

	@Test
	public void authenticateWhenIdTokenNotGeneratedThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scope(OidcScopes.OPENID).build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		given(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
			.willReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		OAuth2AuthorizationCodeAuthenticationToken authentication = new OAuth2AuthorizationCodeAuthenticationToken(
				AUTHORIZATION_CODE, clientPrincipal, authorizationRequest.getRedirectUri(), null);

		given(this.jwtEncoder.encode(any())).willReturn(createJwt());

		willAnswer((answer) -> {
			OAuth2TokenContext context = answer.getArgument(0);
			if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
				return null;
			}
			else {
				return answer.callRealMethod();
			}
		}).given(this.tokenGenerator).generate(any());

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.SERVER_ERROR);
				assertThat(error.getDescription()).contains("The token generator failed to generate the ID token.");
			});
	}

	@Test
	public void authenticateWhenValidCodeThenReturnAccessToken() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		given(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
			.willReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put("dpop_proof", generateDPoPProof("http://localhost/oauth2/token"));
		additionalParameters.put("dpop_method", "POST");
		additionalParameters.put("dpop_target_uri", "http://localhost/oauth2/token");
		OAuth2AuthorizationCodeAuthenticationToken authentication = new OAuth2AuthorizationCodeAuthenticationToken(
				AUTHORIZATION_CODE, clientPrincipal, authorizationRequest.getRedirectUri(), additionalParameters);

		given(this.jwtEncoder.encode(any())).willReturn(createJwt());

		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication = (OAuth2AccessTokenAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		ArgumentCaptor<JwtEncodingContext> jwtEncodingContextCaptor = ArgumentCaptor.forClass(JwtEncodingContext.class);
		verify(this.jwtCustomizer).customize(jwtEncodingContextCaptor.capture());
		JwtEncodingContext jwtEncodingContext = jwtEncodingContextCaptor.getValue();
		assertThat(jwtEncodingContext.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(jwtEncodingContext.<Authentication>getPrincipal())
			.isEqualTo(authorization.getAttribute(Principal.class.getName()));
		assertThat(jwtEncodingContext.getAuthorization()).isEqualTo(authorization);
		assertThat(jwtEncodingContext.getAuthorizedScopes()).isEqualTo(authorization.getAuthorizedScopes());
		assertThat(jwtEncodingContext.getTokenType()).isEqualTo(OAuth2TokenType.ACCESS_TOKEN);
		assertThat(jwtEncodingContext.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(jwtEncodingContext.<OAuth2AuthorizationGrantAuthenticationToken>getAuthorizationGrant())
			.isEqualTo(authentication);
		assertThat(jwtEncodingContext.getJwsHeader()).isNotNull();
		assertThat(jwtEncodingContext.getClaims()).isNotNull();
		assertThat(jwtEncodingContext.<Jwt>get(OAuth2TokenContext.DPOP_PROOF_KEY)).isNotNull();

		ArgumentCaptor<JwtEncoderParameters> jwtEncoderParametersCaptor = ArgumentCaptor
			.forClass(JwtEncoderParameters.class);
		verify(this.jwtEncoder).encode(jwtEncoderParametersCaptor.capture());
		JwtClaimsSet jwtClaimsSet = jwtEncoderParametersCaptor.getValue().getClaims();

		Set<String> scopes = jwtClaimsSet.getClaim(OAuth2ParameterNames.SCOPE);
		assertThat(scopes).isEqualTo(authorization.getAuthorizedScopes());
		assertThat(jwtClaimsSet.getSubject()).isEqualTo(authorization.getPrincipalName());

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();

		assertThat(accessTokenAuthentication.getRegisteredClient().getId())
			.isEqualTo(updatedAuthorization.getRegisteredClientId());
		assertThat(accessTokenAuthentication.getPrincipal()).isEqualTo(clientPrincipal);
		assertThat(accessTokenAuthentication.getAccessToken())
			.isEqualTo(updatedAuthorization.getAccessToken().getToken());
		assertThat(accessTokenAuthentication.getAccessToken().getScopes())
			.isEqualTo(authorization.getAuthorizedScopes());
		assertThat(accessTokenAuthentication.getRefreshToken()).isNotNull();
		assertThat(accessTokenAuthentication.getRefreshToken())
			.isEqualTo(updatedAuthorization.getRefreshToken().getToken());
		OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = updatedAuthorization
			.getToken(OAuth2AuthorizationCode.class);
		assertThat(authorizationCode.isInvalidated()).isTrue();
	}

	@Test
	public void authenticateWhenValidCodeAndAuthenticationRequestThenReturnIdToken() throws Exception {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scope(OidcScopes.OPENID).build();
		OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode("code", Instant.now(),
				Instant.now().plusSeconds(120));
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient, authorizationCode)
			.build();
		given(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
			.willReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		OAuth2AuthorizationCodeAuthenticationToken authentication = new OAuth2AuthorizationCodeAuthenticationToken(
				AUTHORIZATION_CODE, clientPrincipal, authorizationRequest.getRedirectUri(), null);

		given(this.jwtEncoder.encode(any())).willReturn(createJwt());

		Authentication principal = authorization.getAttribute(Principal.class.getName());

		List<SessionInformation> sessions = new ArrayList<>();
		sessions.add(new SessionInformation(principal.getPrincipal(), "session3", Date.from(Instant.now())));
		sessions.add(new SessionInformation(principal.getPrincipal(), "session2",
				Date.from(Instant.now().minus(1, ChronoUnit.HOURS))));
		sessions.add(new SessionInformation(principal.getPrincipal(), "session1",
				Date.from(Instant.now().minus(2, ChronoUnit.HOURS))));
		SessionInformation expectedSession = sessions.get(0); // Most recent
		given(this.sessionRegistry.getAllSessions(eq(principal.getPrincipal()), eq(false))).willReturn(sessions);

		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication = (OAuth2AccessTokenAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		ArgumentCaptor<JwtEncodingContext> jwtEncodingContextCaptor = ArgumentCaptor.forClass(JwtEncodingContext.class);
		verify(this.jwtCustomizer, times(2)).customize(jwtEncodingContextCaptor.capture());
		// Access Token context
		JwtEncodingContext accessTokenContext = jwtEncodingContextCaptor.getAllValues().get(0);
		assertThat(accessTokenContext.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(accessTokenContext.<Authentication>getPrincipal()).isEqualTo(principal);
		assertThat(accessTokenContext.getAuthorization()).isEqualTo(authorization);
		assertThat(accessTokenContext.getAuthorization().getAccessToken()).isNull();
		assertThat(accessTokenContext.getAuthorizedScopes()).isEqualTo(authorization.getAuthorizedScopes());
		assertThat(accessTokenContext.getTokenType()).isEqualTo(OAuth2TokenType.ACCESS_TOKEN);
		assertThat(accessTokenContext.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(accessTokenContext.<OAuth2AuthorizationGrantAuthenticationToken>getAuthorizationGrant())
			.isEqualTo(authentication);
		assertThat(accessTokenContext.getJwsHeader()).isNotNull();
		assertThat(accessTokenContext.getClaims()).isNotNull();
		Map<String, Object> claims = new HashMap<>();
		accessTokenContext.getClaims().claims(claims::putAll);
		assertThat(claims).flatExtracting(OAuth2ParameterNames.SCOPE)
			.containsExactlyInAnyOrder(OidcScopes.OPENID, "scope1");
		// ID Token context
		JwtEncodingContext idTokenContext = jwtEncodingContextCaptor.getAllValues().get(1);
		assertThat(idTokenContext.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(idTokenContext.<Authentication>getPrincipal()).isEqualTo(principal);
		assertThat(idTokenContext.getAuthorization()).isNotEqualTo(authorization);
		assertThat(idTokenContext.getAuthorization().getAccessToken()).isNotNull();
		assertThat(idTokenContext.getAuthorizedScopes()).isEqualTo(authorization.getAuthorizedScopes());
		assertThat(idTokenContext.getTokenType().getValue()).isEqualTo(OidcParameterNames.ID_TOKEN);
		assertThat(idTokenContext.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(idTokenContext.<OAuth2AuthorizationGrantAuthenticationToken>getAuthorizationGrant())
			.isEqualTo(authentication);
		SessionInformation sessionInformation = idTokenContext.get(SessionInformation.class);
		assertThat(sessionInformation).isNotNull();
		assertThat(sessionInformation.getSessionId()).isEqualTo(createHash(expectedSession.getSessionId()));
		assertThat(idTokenContext.getJwsHeader()).isNotNull();
		assertThat(idTokenContext.getClaims()).isNotNull();

		verify(this.jwtEncoder, times(2)).encode(any()); // Access token and ID Token

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();

		assertThat(accessTokenAuthentication.getRegisteredClient().getId())
			.isEqualTo(updatedAuthorization.getRegisteredClientId());
		assertThat(accessTokenAuthentication.getPrincipal()).isEqualTo(clientPrincipal);
		assertThat(accessTokenAuthentication.getAccessToken())
			.isEqualTo(updatedAuthorization.getAccessToken().getToken());
		Set<String> accessTokenScopes = new HashSet<>(updatedAuthorization.getAuthorizedScopes());
		assertThat(accessTokenAuthentication.getAccessToken().getScopes()).isEqualTo(accessTokenScopes);
		assertThat(accessTokenAuthentication.getRefreshToken()).isNotNull();
		assertThat(accessTokenAuthentication.getRefreshToken())
			.isEqualTo(updatedAuthorization.getRefreshToken().getToken());
		OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCodeToken = updatedAuthorization
			.getToken(OAuth2AuthorizationCode.class);
		assertThat(authorizationCodeToken.isInvalidated()).isTrue();
		OAuth2Authorization.Token<OidcIdToken> idToken = updatedAuthorization.getToken(OidcIdToken.class);
		assertThat(idToken).isNotNull();
		assertThat(accessTokenAuthentication.getAdditionalParameters())
			.containsExactly(entry(OidcParameterNames.ID_TOKEN, idToken.getToken().getTokenValue()));
	}

	// gh-296
	@Test
	public void authenticateWhenPublicClientThenRefreshTokenNotIssued() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredPublicClient()
			.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
			.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		given(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
			.willReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.NONE, null);
		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		OAuth2AuthorizationCodeAuthenticationToken authentication = new OAuth2AuthorizationCodeAuthenticationToken(
				AUTHORIZATION_CODE, clientPrincipal, authorizationRequest.getRedirectUri(), null);

		given(this.jwtEncoder.encode(any())).willReturn(createJwt());

		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication = (OAuth2AccessTokenAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		ArgumentCaptor<JwtEncodingContext> jwtEncodingContextCaptor = ArgumentCaptor.forClass(JwtEncodingContext.class);
		verify(this.jwtCustomizer).customize(jwtEncodingContextCaptor.capture());
		JwtEncodingContext jwtEncodingContext = jwtEncodingContextCaptor.getValue();
		assertThat(jwtEncodingContext.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(jwtEncodingContext.<Authentication>getPrincipal())
			.isEqualTo(authorization.getAttribute(Principal.class.getName()));
		assertThat(jwtEncodingContext.getAuthorization()).isEqualTo(authorization);
		assertThat(jwtEncodingContext.getAuthorizedScopes()).isEqualTo(authorization.getAuthorizedScopes());
		assertThat(jwtEncodingContext.getTokenType()).isEqualTo(OAuth2TokenType.ACCESS_TOKEN);
		assertThat(jwtEncodingContext.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
		assertThat(jwtEncodingContext.<OAuth2AuthorizationGrantAuthenticationToken>getAuthorizationGrant())
			.isEqualTo(authentication);
		assertThat(jwtEncodingContext.getJwsHeader()).isNotNull();
		assertThat(jwtEncodingContext.getClaims()).isNotNull();

		ArgumentCaptor<JwtEncoderParameters> jwtEncoderParametersCaptor = ArgumentCaptor
			.forClass(JwtEncoderParameters.class);
		verify(this.jwtEncoder).encode(jwtEncoderParametersCaptor.capture());
		JwtClaimsSet jwtClaimsSet = jwtEncoderParametersCaptor.getValue().getClaims();

		Set<String> scopes = jwtClaimsSet.getClaim(OAuth2ParameterNames.SCOPE);
		assertThat(scopes).isEqualTo(authorization.getAuthorizedScopes());
		assertThat(jwtClaimsSet.getSubject()).isEqualTo(authorization.getPrincipalName());

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();

		assertThat(accessTokenAuthentication.getRegisteredClient().getId())
			.isEqualTo(updatedAuthorization.getRegisteredClientId());
		assertThat(accessTokenAuthentication.getPrincipal()).isEqualTo(clientPrincipal);
		assertThat(accessTokenAuthentication.getAccessToken())
			.isEqualTo(updatedAuthorization.getAccessToken().getToken());
		assertThat(accessTokenAuthentication.getAccessToken().getScopes())
			.isEqualTo(authorization.getAuthorizedScopes());
		assertThat(accessTokenAuthentication.getRefreshToken()).isNull();
		OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = updatedAuthorization
			.getToken(OAuth2AuthorizationCode.class);
		assertThat(authorizationCode.isInvalidated()).isTrue();
	}

	@Test
	public void authenticateWhenTokenTimeToLiveConfiguredThenTokenExpirySet() {
		Duration accessTokenTTL = Duration.ofHours(2);
		Duration refreshTokenTTL = Duration.ofDays(1);
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.tokenSettings(TokenSettings.builder()
				.accessTokenTimeToLive(accessTokenTTL)
				.refreshTokenTimeToLive(refreshTokenTTL)
				.build())
			.build();

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		given(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
			.willReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		OAuth2AuthorizationCodeAuthenticationToken authentication = new OAuth2AuthorizationCodeAuthenticationToken(
				AUTHORIZATION_CODE, clientPrincipal, authorizationRequest.getRedirectUri(), null);

		Instant accessTokenIssuedAt = Instant.now();
		Instant accessTokenExpiresAt = accessTokenIssuedAt.plus(accessTokenTTL);
		given(this.jwtEncoder.encode(any())).willReturn(createJwt(accessTokenIssuedAt, accessTokenExpiresAt));

		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication = (OAuth2AccessTokenAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();

		assertThat(accessTokenAuthentication.getAccessToken())
			.isEqualTo(updatedAuthorization.getAccessToken().getToken());
		Instant expectedAccessTokenExpiresAt = accessTokenAuthentication.getAccessToken()
			.getIssuedAt()
			.plus(accessTokenTTL);
		assertThat(accessTokenAuthentication.getAccessToken().getExpiresAt())
			.isBetween(expectedAccessTokenExpiresAt.minusSeconds(1), expectedAccessTokenExpiresAt.plusSeconds(1));

		assertThat(accessTokenAuthentication.getRefreshToken())
			.isEqualTo(updatedAuthorization.getRefreshToken().getToken());
		Instant expectedRefreshTokenExpiresAt = accessTokenAuthentication.getRefreshToken()
			.getIssuedAt()
			.plus(refreshTokenTTL);
		assertThat(accessTokenAuthentication.getRefreshToken().getExpiresAt())
			.isBetween(expectedRefreshTokenExpiresAt.minusSeconds(1), expectedRefreshTokenExpiresAt.plusSeconds(1));
	}

	@Test
	public void authenticateWhenRefreshTokenGrantNotConfiguredThenRefreshTokenNotIssued() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantTypes((grantTypes) -> grantTypes.remove(AuthorizationGrantType.REFRESH_TOKEN))
			.build();

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		given(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
			.willReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		OAuth2AuthorizationCodeAuthenticationToken authentication = new OAuth2AuthorizationCodeAuthenticationToken(
				AUTHORIZATION_CODE, clientPrincipal, authorizationRequest.getRedirectUri(), null);

		given(this.jwtEncoder.encode(any())).willReturn(createJwt());

		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication = (OAuth2AccessTokenAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		assertThat(accessTokenAuthentication.getRefreshToken()).isNull();
	}

	@Test
	public void authenticateWhenAccessTokenFormatReferenceThenAccessTokenGeneratorCalled() {
		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.tokenSettings(TokenSettings.builder()
						.accessTokenFormat(OAuth2TokenFormat.REFERENCE)
						.build())
				.build();
		// @formatter:on
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		given(this.authorizationService.findByToken(eq(AUTHORIZATION_CODE), eq(AUTHORIZATION_CODE_TOKEN_TYPE)))
			.willReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		OAuth2AuthorizationCodeAuthenticationToken authentication = new OAuth2AuthorizationCodeAuthenticationToken(
				AUTHORIZATION_CODE, clientPrincipal, authorizationRequest.getRedirectUri(), null);

		this.authenticationProvider.authenticate(authentication);

		verify(this.accessTokenCustomizer).customize(any());
	}

	private static Jwt createJwt() {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(1, ChronoUnit.HOURS);
		return createJwt(issuedAt, expiresAt);
	}

	private static Jwt createJwt(Instant issuedAt, Instant expiresAt) {
		return Jwt.withTokenValue("token")
			.header(JoseHeaderNames.ALG, SignatureAlgorithm.RS256.getName())
			.issuedAt(issuedAt)
			.expiresAt(expiresAt)
			.build();
	}

	private static String createHash(String value) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(value.getBytes(StandardCharsets.US_ASCII));
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
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
