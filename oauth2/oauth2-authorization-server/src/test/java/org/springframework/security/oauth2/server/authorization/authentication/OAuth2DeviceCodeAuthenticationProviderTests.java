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
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Function;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2UserCode;
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
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests for {@link OAuth2DeviceCodeAuthenticationProvider}.
 *
 * @author Steve Riesenberg
 */
public class OAuth2DeviceCodeAuthenticationProviderTests {

	private static final String DEVICE_CODE = "EfYu_0jEL";

	private static final String USER_CODE = "BCDF-GHJK";

	private static final String ACCESS_TOKEN = "abc123";

	private static final String REFRESH_TOKEN = "xyz456";

	private OAuth2AuthorizationService authorizationService;

	private OAuth2TokenGenerator<OAuth2Token> tokenGenerator;

	private JwtEncoder dPoPProofJwtEncoder;

	private OAuth2DeviceCodeAuthenticationProvider authenticationProvider;

	@BeforeEach
	@SuppressWarnings("unchecked")
	public void setUp() {
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.tokenGenerator = mock(OAuth2TokenGenerator.class);
		JWKSet clientJwkSet = new JWKSet(TestJwks.DEFAULT_EC_JWK);
		JWKSource<SecurityContext> clientJwkSource = (jwkSelector, securityContext) -> jwkSelector.select(clientJwkSet);
		this.dPoPProofJwtEncoder = new NimbusJwtEncoder(clientJwkSource);
		this.authenticationProvider = new OAuth2DeviceCodeAuthenticationProvider(this.authorizationService,
				this.tokenGenerator);
		mockAuthorizationServerContext();
	}

	@AfterEach
	public void tearDown() {
		AuthorizationServerContextHolder.resetContext();
	}

	@Test
	public void constructorWhenAuthorizationServiceIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2DeviceCodeAuthenticationProvider(null, this.tokenGenerator))
				.withMessage("authorizationService cannot be null");
		// @formatter:on
	}

	@Test
	public void constructorWhenTokenGeneratorIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OAuth2DeviceCodeAuthenticationProvider(this.authorizationService, null))
				.withMessage("tokenGenerator cannot be null");
		// @formatter:on
	}

	@Test
	public void supportsWhenTypeOAuth2DeviceCodeAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2DeviceCodeAuthenticationToken.class)).isTrue();
	}

	@Test
	public void authenticateWhenClientNotAuthenticatedThenThrowOAuth2AuthenticationException() {
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken("client-1",
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null, null);
		Authentication authentication = new OAuth2DeviceCodeAuthenticationToken(DEVICE_CODE, clientPrincipal, null);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
		// @formatter:on
	}

	@Test
	public void authenticateWhenAuthorizationNotFoundThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		Authentication authentication = createAuthentication(registeredClient);
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(null);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
		// @formatter:on

		verify(this.authorizationService).findByToken(DEVICE_CODE,
				OAuth2DeviceCodeAuthenticationProvider.DEVICE_CODE_TOKEN_TYPE);
		verifyNoMoreInteractions(this.authorizationService);
		verifyNoInteractions(this.tokenGenerator);
	}

	@Test
	public void authenticateWhenRegisteredClientDoesNotMatchClientIdThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		RegisteredClient registeredClient2 = TestRegisteredClients.registeredClient2().build();
		Authentication authentication = createAuthentication(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient2)
			.token(createDeviceCode())
			.build();
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(authorization);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
		// @formatter:on

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).findByToken(DEVICE_CODE,
				OAuth2DeviceCodeAuthenticationProvider.DEVICE_CODE_TOKEN_TYPE);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		verifyNoMoreInteractions(this.authorizationService);
		verifyNoInteractions(this.tokenGenerator);

		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();
		// @formatter:off
		assertThat(updatedAuthorization.getToken(OAuth2DeviceCode.class))
				.extracting(isInvalidated())
				.isEqualTo(true);
		// @formatter:on
	}

	@Test
	public void authenticateWhenUserCodeIsNotInvalidatedThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		Authentication authentication = createAuthentication(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.token(createDeviceCode())
			.token(createUserCode())
			.build();
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(authorization);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2DeviceCodeAuthenticationProvider.AUTHORIZATION_PENDING);
		// @formatter:on

		verify(this.authorizationService).findByToken(DEVICE_CODE,
				OAuth2DeviceCodeAuthenticationProvider.DEVICE_CODE_TOKEN_TYPE);
		verifyNoMoreInteractions(this.authorizationService);
		verifyNoInteractions(this.tokenGenerator);
	}

	@Test
	public void authenticateWhenDeviceCodeAndUserCodeAreInvalidatedThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		Authentication authentication = createAuthentication(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.token(createDeviceCode(), withInvalidated())
			.token(createUserCode(), withInvalidated())
			.build();
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(authorization);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.ACCESS_DENIED);
		// @formatter:on

		verify(this.authorizationService).findByToken(DEVICE_CODE,
				OAuth2DeviceCodeAuthenticationProvider.DEVICE_CODE_TOKEN_TYPE);
		verifyNoMoreInteractions(this.authorizationService);
		verifyNoInteractions(this.tokenGenerator);
	}

	@Test
	public void authenticateWhenDeviceCodeIsExpiredThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		Authentication authentication = createAuthentication(registeredClient);
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.token(createExpiredDeviceCode())
			.token(createUserCode())
			.build();
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(authorization);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2DeviceCodeAuthenticationProvider.EXPIRED_TOKEN);
		// @formatter:on

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).findByToken(DEVICE_CODE,
				OAuth2DeviceCodeAuthenticationProvider.DEVICE_CODE_TOKEN_TYPE);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		verifyNoMoreInteractions(this.authorizationService);
		verifyNoInteractions(this.tokenGenerator);

		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();
		// @formatter:off
		assertThat(updatedAuthorization.getToken(OAuth2DeviceCode.class))
				.extracting(isInvalidated())
				.isEqualTo(true);
		// @formatter:on
	}

	@Test
	public void authenticateWhenAccessTokenIsNullThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		Authentication authentication = createAuthentication(registeredClient);
		// @formatter:off
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.token(createDeviceCode())
				.token(createUserCode(), withInvalidated())
				.attribute(Principal.class.getName(), authentication.getPrincipal())
				.build();
		// @formatter:on
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(authorization);
		given(this.tokenGenerator.generate(any(OAuth2TokenContext.class))).willReturn(null);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.withMessage("The token generator failed to generate the access token.")
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.SERVER_ERROR);
		// @formatter:on

		verify(this.authorizationService).findByToken(DEVICE_CODE,
				OAuth2DeviceCodeAuthenticationProvider.DEVICE_CODE_TOKEN_TYPE);
		verify(this.tokenGenerator).generate(any(OAuth2TokenContext.class));
		verifyNoMoreInteractions(this.authorizationService, this.tokenGenerator);
	}

	@Test
	public void authenticateWhenRefreshTokenIsNullThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		Authentication authentication = createAuthentication(registeredClient);
		// @formatter:off
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.token(createDeviceCode())
				.token(createUserCode(), withInvalidated())
				.attribute(Principal.class.getName(), authentication.getPrincipal())
				.build();
		// @formatter:on
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(authorization);
		given(this.tokenGenerator.generate(any(OAuth2TokenContext.class))).willReturn(createAccessToken(),
				(OAuth2RefreshToken) null);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.withMessage("The token generator failed to generate the refresh token.")
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.SERVER_ERROR);
		// @formatter:on

		verify(this.authorizationService).findByToken(DEVICE_CODE,
				OAuth2DeviceCodeAuthenticationProvider.DEVICE_CODE_TOKEN_TYPE);
		verify(this.tokenGenerator, times(2)).generate(any(OAuth2TokenContext.class));
		verifyNoMoreInteractions(this.authorizationService, this.tokenGenerator);
	}

	@Test
	public void authenticateWhenTokenGeneratorReturnsWrongTypeThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		Authentication authentication = createAuthentication(registeredClient);
		// @formatter:off
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.token(createDeviceCode())
				.token(createUserCode(), withInvalidated())
				.attribute(Principal.class.getName(), authentication.getPrincipal())
				.build();
		// @formatter:on
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(authorization);
		OAuth2AccessToken accessToken = createAccessToken();
		given(this.tokenGenerator.generate(any(OAuth2TokenContext.class))).willReturn(accessToken, accessToken);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.withMessage("The token generator failed to generate the refresh token.")
				.extracting(OAuth2AuthenticationException::getError)
				.extracting(OAuth2Error::getErrorCode)
				.isEqualTo(OAuth2ErrorCodes.SERVER_ERROR);
		// @formatter:on

		verify(this.authorizationService).findByToken(DEVICE_CODE,
				OAuth2DeviceCodeAuthenticationProvider.DEVICE_CODE_TOKEN_TYPE);
		verify(this.tokenGenerator, times(2)).generate(any(OAuth2TokenContext.class));
		verifyNoMoreInteractions(this.authorizationService, this.tokenGenerator);
	}

	@Test
	public void authenticateWhenValidDeviceCodeThenReturnAccessTokenAndRefreshToken() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null);
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put("dpop_proof", generateDPoPProof("http://localhost/oauth2/token"));
		additionalParameters.put("dpop_method", "POST");
		additionalParameters.put("dpop_target_uri", "http://localhost/oauth2/token");
		OAuth2DeviceCodeAuthenticationToken authentication = new OAuth2DeviceCodeAuthenticationToken(DEVICE_CODE,
				clientPrincipal, additionalParameters);

		// @formatter:off
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
				.token(createDeviceCode())
				.token(createUserCode(), withInvalidated())
				.attribute(Principal.class.getName(), authentication.getPrincipal())
				.build();
		// @formatter:on
		given(this.authorizationService.findByToken(anyString(), any(OAuth2TokenType.class))).willReturn(authorization);
		OAuth2AccessToken accessToken = createAccessToken();
		OAuth2RefreshToken refreshToken = createRefreshToken();
		given(this.tokenGenerator.generate(any(OAuth2TokenContext.class))).willReturn(accessToken, refreshToken);
		OAuth2AccessTokenAuthenticationToken authenticationResult = (OAuth2AccessTokenAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);
		assertThat(authenticationResult.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(authenticationResult.getPrincipal()).isEqualTo(authentication.getPrincipal());
		assertThat(authenticationResult.getAccessToken()).isEqualTo(accessToken);
		assertThat(authenticationResult.getRefreshToken()).isEqualTo(refreshToken);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		ArgumentCaptor<OAuth2TokenContext> tokenContextCaptor = ArgumentCaptor.forClass(OAuth2TokenContext.class);
		verify(this.authorizationService).findByToken(DEVICE_CODE,
				OAuth2DeviceCodeAuthenticationProvider.DEVICE_CODE_TOKEN_TYPE);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		verify(this.tokenGenerator, times(2)).generate(tokenContextCaptor.capture());
		verifyNoMoreInteractions(this.authorizationService, this.tokenGenerator);

		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();
		// @formatter:off
		assertThat(updatedAuthorization.getToken(OAuth2DeviceCode.class))
				.extracting(isInvalidated())
				.isEqualTo(true);
		// @formatter:on
		assertThat(updatedAuthorization.getAccessToken().getToken()).isEqualTo(accessToken);
		assertThat(updatedAuthorization.getRefreshToken().getToken()).isEqualTo(refreshToken);

		for (OAuth2TokenContext tokenContext : tokenContextCaptor.getAllValues()) {
			assertThat(tokenContext.getRegisteredClient()).isEqualTo(registeredClient);
			assertThat(tokenContext.<Authentication>getPrincipal()).isEqualTo(authentication.getPrincipal());
			assertThat(tokenContext.getAuthorizationServerContext()).isNotNull();
			assertThat(tokenContext.getAuthorization()).isEqualTo(authorization);
			assertThat(tokenContext.getAuthorizedScopes()).isEqualTo(authorization.getAuthorizedScopes());
			assertThat(tokenContext.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.DEVICE_CODE);
			assertThat(tokenContext.<Authentication>getAuthorizationGrant()).isEqualTo(authentication);
			assertThat(tokenContext.<Jwt>get(OAuth2TokenContext.DPOP_PROOF_KEY)).isNotNull();
		}
		assertThat(tokenContextCaptor.getAllValues().get(0).getTokenType()).isEqualTo(OAuth2TokenType.ACCESS_TOKEN);
		assertThat(tokenContextCaptor.getAllValues().get(1).getTokenType()).isEqualTo(OAuth2TokenType.REFRESH_TOKEN);
	}

	private static void mockAuthorizationServerContext() {
		AuthorizationServerSettings authorizationServerSettings = AuthorizationServerSettings.builder().build();
		TestAuthorizationServerContext authorizationServerContext = new TestAuthorizationServerContext(
				authorizationServerSettings, () -> "https://provider.com");
		AuthorizationServerContextHolder.setContext(authorizationServerContext);
	}

	private static OAuth2DeviceCodeAuthenticationToken createAuthentication(RegisteredClient registeredClient) {
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null);
		return new OAuth2DeviceCodeAuthenticationToken(DEVICE_CODE, clientPrincipal, null);
	}

	private static OAuth2DeviceCode createDeviceCode() {
		Instant issuedAt = Instant.now();
		return new OAuth2DeviceCode(DEVICE_CODE, issuedAt, issuedAt.plus(30, ChronoUnit.MINUTES));
	}

	private static OAuth2DeviceCode createExpiredDeviceCode() {
		Instant issuedAt = Instant.now().minus(45, ChronoUnit.MINUTES);
		return new OAuth2DeviceCode(DEVICE_CODE, issuedAt, issuedAt.plus(30, ChronoUnit.MINUTES));
	}

	private static OAuth2UserCode createUserCode() {
		Instant issuedAt = Instant.now();
		return new OAuth2UserCode(USER_CODE, issuedAt, issuedAt.plus(30, ChronoUnit.MINUTES));
	}

	private static OAuth2AccessToken createAccessToken() {
		Instant issuedAt = Instant.now();
		return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, ACCESS_TOKEN, issuedAt,
				issuedAt.plus(30, ChronoUnit.MINUTES));
	}

	private static OAuth2RefreshToken createRefreshToken() {
		Instant issuedAt = Instant.now();
		return new OAuth2RefreshToken(REFRESH_TOKEN, issuedAt, issuedAt.plus(30, ChronoUnit.MINUTES));
	}

	private static Consumer<Map<String, Object>> withInvalidated() {
		return (metadata) -> metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true);
	}

	public static Function<OAuth2Authorization.Token<? extends OAuth2Token>, Boolean> isInvalidated() {
		return (token) -> token.getMetadata(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME);
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
