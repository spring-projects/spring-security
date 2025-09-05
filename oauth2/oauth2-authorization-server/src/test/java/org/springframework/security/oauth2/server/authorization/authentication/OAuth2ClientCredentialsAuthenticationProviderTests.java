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

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashMap;
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
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
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
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
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
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link OAuth2ClientCredentialsAuthenticationProvider}.
 *
 * @author Alexey Nesterov
 * @author Joe Grandja
 */
public class OAuth2ClientCredentialsAuthenticationProviderTests {

	private OAuth2AuthorizationService authorizationService;

	private JwtEncoder jwtEncoder;

	private OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer;

	private OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer;

	private OAuth2TokenGenerator<?> tokenGenerator;

	private JwtEncoder dPoPProofJwtEncoder;

	private OAuth2ClientCredentialsAuthenticationProvider authenticationProvider;

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
		OAuth2TokenGenerator<OAuth2Token> delegatingTokenGenerator = new DelegatingOAuth2TokenGenerator(jwtGenerator,
				accessTokenGenerator);
		this.tokenGenerator = spy(new OAuth2TokenGenerator<OAuth2Token>() {
			@Override
			public OAuth2Token generate(OAuth2TokenContext context) {
				return delegatingTokenGenerator.generate(context);
			}
		});
		JWKSet clientJwkSet = new JWKSet(TestJwks.DEFAULT_EC_JWK);
		JWKSource<SecurityContext> clientJwkSource = (jwkSelector, securityContext) -> jwkSelector.select(clientJwkSet);
		this.dPoPProofJwtEncoder = new NimbusJwtEncoder(clientJwkSource);
		this.authenticationProvider = new OAuth2ClientCredentialsAuthenticationProvider(this.authorizationService,
				this.tokenGenerator);
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
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> new OAuth2ClientCredentialsAuthenticationProvider(null, this.tokenGenerator))
			.withMessage("authorizationService cannot be null");
	}

	@Test
	public void constructorWhenTokenGeneratorNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> new OAuth2ClientCredentialsAuthenticationProvider(this.authorizationService, null))
			.withMessage("tokenGenerator cannot be null");
	}

	@Test
	public void supportsWhenSupportedAuthenticationThenTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2ClientCredentialsAuthenticationToken.class)).isTrue();
	}

	@Test
	public void supportsWhenUnsupportedAuthenticationThenFalse() {
		assertThat(this.authenticationProvider.supports(OAuth2AuthorizationCodeAuthenticationToken.class)).isFalse();
	}

	@Test
	public void setAuthenticationValidatorWhenNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.authenticationProvider.setAuthenticationValidator(null))
			.withMessage("authenticationValidator cannot be null");
	}

	@Test
	public void authenticateWhenClientPrincipalNotOAuth2ClientAuthenticationTokenThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2().build();
		TestingAuthenticationToken clientPrincipal = new TestingAuthenticationToken(registeredClient.getClientId(),
				registeredClient.getClientSecret());
		OAuth2ClientCredentialsAuthenticationToken authentication = new OAuth2ClientCredentialsAuthenticationToken(
				clientPrincipal, null, null);

		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.extracting(OAuth2AuthenticationException::getError)
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenClientPrincipalNotAuthenticatedThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
				registeredClient.getClientId(), ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
				registeredClient.getClientSecret(), null);
		OAuth2ClientCredentialsAuthenticationToken authentication = new OAuth2ClientCredentialsAuthenticationToken(
				clientPrincipal, null, null);

		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.extracting(OAuth2AuthenticationException::getError)
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenClientNotAuthorizedToRequestTokenThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2()
			.authorizationGrantTypes((grantTypes) -> grantTypes.remove(AuthorizationGrantType.CLIENT_CREDENTIALS))
			.build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2ClientCredentialsAuthenticationToken authentication = new OAuth2ClientCredentialsAuthenticationToken(
				clientPrincipal, null, null);

		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.extracting(OAuth2AuthenticationException::getError)
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
	}

	@Test
	public void authenticateWhenInvalidScopeThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2ClientCredentialsAuthenticationToken authentication = new OAuth2ClientCredentialsAuthenticationToken(
				clientPrincipal, Collections.singleton("invalid-scope"), null);

		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.extracting(OAuth2AuthenticationException::getError)
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE);
	}

	@Test
	public void authenticateWhenScopeRequestedThenAccessTokenContainsScope() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		Set<String> requestedScope = Collections.singleton("scope1");
		OAuth2ClientCredentialsAuthenticationToken authentication = new OAuth2ClientCredentialsAuthenticationToken(
				clientPrincipal, requestedScope, null);

		given(this.jwtEncoder.encode(any())).willReturn(createJwt(Collections.singleton("mapped-scoped")));

		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication = (OAuth2AccessTokenAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);
		assertThat(accessTokenAuthentication.getAccessToken().getScopes()).isEqualTo(requestedScope);
	}

	@Test
	public void authenticateWhenNoScopeRequestedThenAccessTokenDoesNotContainScope() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2ClientCredentialsAuthenticationToken authentication = new OAuth2ClientCredentialsAuthenticationToken(
				clientPrincipal, null, null);

		given(this.jwtEncoder.encode(any())).willReturn(createJwt(Collections.singleton("mapped-scoped")));

		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication = (OAuth2AccessTokenAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);
		assertThat(accessTokenAuthentication.getAccessToken().getScopes()).isEmpty();
	}

	@Test
	public void authenticateWhenAccessTokenNotGeneratedThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2ClientCredentialsAuthenticationToken authentication = new OAuth2ClientCredentialsAuthenticationToken(
				clientPrincipal, null, null);

		doReturn(null).when(this.tokenGenerator).generate(any());

		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.extracting(OAuth2AuthenticationException::getError)
			.satisfies((error) -> {
				assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.SERVER_ERROR);
				assertThat(error.getDescription()).contains("The token generator failed to generate the access token.");
			});
	}

	@Test
	public void authenticateWhenValidAuthenticationThenReturnAccessToken() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put("dpop_proof", generateDPoPProof("http://localhost/oauth2/token"));
		additionalParameters.put("dpop_method", "POST");
		additionalParameters.put("dpop_target_uri", "http://localhost/oauth2/token");
		OAuth2ClientCredentialsAuthenticationToken authentication = new OAuth2ClientCredentialsAuthenticationToken(
				clientPrincipal, null, additionalParameters);

		given(this.jwtEncoder.encode(any())).willReturn(createJwt(registeredClient.getScopes()));

		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication = (OAuth2AccessTokenAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		ArgumentCaptor<JwtEncodingContext> jwtEncodingContextCaptor = ArgumentCaptor.forClass(JwtEncodingContext.class);
		verify(this.jwtCustomizer).customize(jwtEncodingContextCaptor.capture());
		JwtEncodingContext jwtEncodingContext = jwtEncodingContextCaptor.getValue();
		assertThat(jwtEncodingContext.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(jwtEncodingContext.<Authentication>getPrincipal()).isEqualTo(clientPrincipal);
		assertThat(jwtEncodingContext.getAuthorization()).isNull();
		assertThat(jwtEncodingContext.getTokenType()).isEqualTo(OAuth2TokenType.ACCESS_TOKEN);
		assertThat(jwtEncodingContext.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS);
		assertThat(jwtEncodingContext.<OAuth2AuthorizationGrantAuthenticationToken>getAuthorizationGrant())
			.isEqualTo(authentication);
		assertThat(jwtEncodingContext.getJwsHeader()).isNotNull();
		assertThat(jwtEncodingContext.getClaims()).isNotNull();
		assertThat(jwtEncodingContext.<Jwt>get(OAuth2TokenContext.DPOP_PROOF_KEY)).isNotNull();

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization authorization = authorizationCaptor.getValue();
		assertThat(jwtEncodingContext.getAuthorizedScopes()).isEqualTo(authorization.getAuthorizedScopes());
		assertThat(authorization.getRegisteredClientId()).isEqualTo(clientPrincipal.getRegisteredClient().getId());
		assertThat(authorization.getPrincipalName()).isEqualTo(clientPrincipal.getName());
		assertThat(authorization.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS);
		assertThat(authorization.getAccessToken()).isNotNull();
		assertThat(authorization.getAuthorizedScopes()).isNotNull();
		assertThat(authorization.getAccessToken().getToken().getScopes())
			.isEqualTo(authorization.getAuthorizedScopes());
		assertThat(accessTokenAuthentication.getPrincipal()).isEqualTo(clientPrincipal);
		assertThat(accessTokenAuthentication.getAccessToken()).isEqualTo(authorization.getAccessToken().getToken());
	}

	@Test
	public void authenticateWhenAccessTokenFormatReferenceThenAccessTokenGeneratorCalled() {
		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2()
				.tokenSettings(TokenSettings.builder()
						.accessTokenFormat(OAuth2TokenFormat.REFERENCE)
						.build())
				.build();
		// @formatter:on
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2ClientCredentialsAuthenticationToken authentication = new OAuth2ClientCredentialsAuthenticationToken(
				clientPrincipal, null, null);

		this.authenticationProvider.authenticate(authentication);

		verify(this.accessTokenCustomizer).customize(any());
	}

	@Test
	public void authenticateWhenCustomAuthenticationValidatorThenUsed() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient2().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2ClientCredentialsAuthenticationToken authentication = new OAuth2ClientCredentialsAuthenticationToken(
				clientPrincipal, registeredClient.getScopes(), null);

		@SuppressWarnings("unchecked")
		Consumer<OAuth2ClientCredentialsAuthenticationContext> authenticationValidator = mock(Consumer.class);
		this.authenticationProvider.setAuthenticationValidator(authenticationValidator);

		given(this.jwtEncoder.encode(any())).willReturn(createJwt(registeredClient.getScopes()));

		this.authenticationProvider.authenticate(authentication);

		verify(authenticationValidator).accept(any(OAuth2ClientCredentialsAuthenticationContext.class));
	}

	private static Jwt createJwt(Set<String> scope) {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(1, ChronoUnit.HOURS);
		return Jwt.withTokenValue("token")
			.header(JoseHeaderNames.ALG, SignatureAlgorithm.RS256.getName())
			.issuedAt(issuedAt)
			.expiresAt(expiresAt)
			.claim(OAuth2ParameterNames.SCOPE, scope)
			.build();
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
