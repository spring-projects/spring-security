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

import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
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
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
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
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link OAuth2RefreshTokenAuthenticationProvider}.
 *
 * @author Alexey Nesterov
 * @author Joe Grandja
 * @author Anoop Garlapati
 * @since 0.0.3
 */
public class OAuth2RefreshTokenAuthenticationProviderTests {

	private OAuth2AuthorizationService authorizationService;

	private JwtEncoder jwtEncoder;

	private OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer;

	private OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer;

	private OAuth2TokenGenerator<?> tokenGenerator;

	private JwtEncoder dPoPProofJwtEncoder;

	private OAuth2RefreshTokenAuthenticationProvider authenticationProvider;

	@BeforeEach
	public void setUp() {
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.jwtEncoder = mock(JwtEncoder.class);
		given(this.jwtEncoder.encode(any())).willReturn(createJwt(Collections.singleton("scope1")));
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
		this.authenticationProvider = new OAuth2RefreshTokenAuthenticationProvider(this.authorizationService,
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
		assertThatThrownBy(() -> new OAuth2RefreshTokenAuthenticationProvider(null, this.tokenGenerator))
			.isInstanceOf(IllegalArgumentException.class)
			.extracting(Throwable::getMessage)
			.isEqualTo("authorizationService cannot be null");
	}

	@Test
	public void constructorWhenTokenGeneratorNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2RefreshTokenAuthenticationProvider(this.authorizationService, null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("tokenGenerator cannot be null");
	}

	@Test
	public void supportsWhenSupportedAuthenticationThenTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2RefreshTokenAuthenticationToken.class)).isTrue();
	}

	@Test
	public void supportsWhenUnsupportedAuthenticationThenFalse() {
		assertThat(this.authenticationProvider.supports(OAuth2ClientCredentialsAuthenticationToken.class)).isFalse();
	}

	@Test
	public void authenticateWhenValidRefreshTokenThenReturnAccessToken() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		given(this.authorizationService.findByToken(eq(authorization.getRefreshToken().getToken().getTokenValue()),
				eq(OAuth2TokenType.REFRESH_TOKEN)))
			.willReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put("dpop_proof", generateDPoPProof("http://localhost/oauth2/token"));
		additionalParameters.put("dpop_method", "POST");
		additionalParameters.put("dpop_target_uri", "http://localhost/oauth2/token");
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getRefreshToken().getToken().getTokenValue(), clientPrincipal, null,
				additionalParameters);

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
		assertThat(jwtEncodingContext.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.REFRESH_TOKEN);
		assertThat(jwtEncodingContext.<OAuth2AuthorizationGrantAuthenticationToken>getAuthorizationGrant())
			.isEqualTo(authentication);
		assertThat(jwtEncodingContext.getJwsHeader()).isNotNull();
		assertThat(jwtEncodingContext.getClaims()).isNotNull();
		assertThat(jwtEncodingContext.<Jwt>get(OAuth2TokenContext.DPOP_PROOF_KEY)).isNotNull();

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();

		assertThat(accessTokenAuthentication.getRegisteredClient().getId())
			.isEqualTo(updatedAuthorization.getRegisteredClientId());
		assertThat(accessTokenAuthentication.getPrincipal()).isEqualTo(clientPrincipal);
		assertThat(accessTokenAuthentication.getAccessToken())
			.isEqualTo(updatedAuthorization.getAccessToken().getToken());
		assertThat(updatedAuthorization.getAccessToken()).isNotEqualTo(authorization.getAccessToken());
		assertThat(accessTokenAuthentication.getRefreshToken())
			.isEqualTo(updatedAuthorization.getRefreshToken().getToken());
		// By default, refresh token is reused
		assertThat(updatedAuthorization.getRefreshToken()).isEqualTo(authorization.getRefreshToken());
	}

	@Test
	public void authenticateWhenValidRefreshTokenThenReturnIdToken() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scope(OidcScopes.OPENID).build();
		OidcIdToken authorizedIdToken = OidcIdToken.withTokenValue("id-token")
			.issuer("https://provider.com")
			.subject("subject")
			.issuedAt(Instant.now())
			.expiresAt(Instant.now().plusSeconds(60))
			.claim("sid", "sessionId-1234")
			.claim(IdTokenClaimNames.AUTH_TIME, Date.from(Instant.now()))
			.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.token(authorizedIdToken)
			.build();
		given(this.authorizationService.findByToken(eq(authorization.getRefreshToken().getToken().getTokenValue()),
				eq(OAuth2TokenType.REFRESH_TOKEN)))
			.willReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getRefreshToken().getToken().getTokenValue(), clientPrincipal, null, null);

		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication = (OAuth2AccessTokenAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		ArgumentCaptor<JwtEncodingContext> jwtEncodingContextCaptor = ArgumentCaptor.forClass(JwtEncodingContext.class);
		verify(this.jwtCustomizer, times(2)).customize(jwtEncodingContextCaptor.capture());
		// Access Token context
		JwtEncodingContext accessTokenContext = jwtEncodingContextCaptor.getAllValues().get(0);
		assertThat(accessTokenContext.getRegisteredClient()).isEqualTo(registeredClient);
		assertThat(accessTokenContext.<Authentication>getPrincipal())
			.isEqualTo(authorization.getAttribute(Principal.class.getName()));
		assertThat(accessTokenContext.getAuthorization()).isEqualTo(authorization);
		assertThat(accessTokenContext.getAuthorizedScopes()).isEqualTo(authorization.getAuthorizedScopes());
		assertThat(accessTokenContext.getTokenType()).isEqualTo(OAuth2TokenType.ACCESS_TOKEN);
		assertThat(accessTokenContext.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.REFRESH_TOKEN);
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
		assertThat(idTokenContext.<Authentication>getPrincipal())
			.isEqualTo(authorization.getAttribute(Principal.class.getName()));
		assertThat(idTokenContext.getAuthorization()).isNotEqualTo(authorization);
		assertThat(idTokenContext.getAuthorization().getAccessToken()).isNotEqualTo(authorization.getAccessToken());
		assertThat(idTokenContext.getAuthorizedScopes()).isEqualTo(authorization.getAuthorizedScopes());
		assertThat(idTokenContext.getTokenType().getValue()).isEqualTo(OidcParameterNames.ID_TOKEN);
		assertThat(idTokenContext.getAuthorizationGrantType()).isEqualTo(AuthorizationGrantType.REFRESH_TOKEN);
		assertThat(idTokenContext.<OAuth2AuthorizationGrantAuthenticationToken>getAuthorizationGrant())
			.isEqualTo(authentication);
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
		assertThat(updatedAuthorization.getAccessToken()).isNotEqualTo(authorization.getAccessToken());
		OAuth2Authorization.Token<OidcIdToken> idToken = updatedAuthorization.getToken(OidcIdToken.class);
		assertThat(idToken).isNotNull();
		assertThat(accessTokenAuthentication.getAdditionalParameters())
			.containsExactly(entry(OidcParameterNames.ID_TOKEN, idToken.getToken().getTokenValue()));
		assertThat(accessTokenAuthentication.getRefreshToken())
			.isEqualTo(updatedAuthorization.getRefreshToken().getToken());
		// By default, refresh token is reused
		assertThat(updatedAuthorization.getRefreshToken()).isEqualTo(authorization.getRefreshToken());
	}

	@Test
	public void authenticateWhenReuseRefreshTokensFalseThenReturnNewRefreshToken() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.tokenSettings(TokenSettings.builder().reuseRefreshTokens(false).build())
			.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		given(this.authorizationService.findByToken(eq(authorization.getRefreshToken().getToken().getTokenValue()),
				eq(OAuth2TokenType.REFRESH_TOKEN)))
			.willReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getRefreshToken().getToken().getTokenValue(), clientPrincipal, null, null);

		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication = (OAuth2AccessTokenAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		ArgumentCaptor<OAuth2Authorization> authorizationCaptor = ArgumentCaptor.forClass(OAuth2Authorization.class);
		verify(this.authorizationService).save(authorizationCaptor.capture());
		OAuth2Authorization updatedAuthorization = authorizationCaptor.getValue();

		assertThat(accessTokenAuthentication.getRefreshToken())
			.isEqualTo(updatedAuthorization.getRefreshToken().getToken());
		assertThat(updatedAuthorization.getRefreshToken()).isNotEqualTo(authorization.getRefreshToken());

		ArgumentCaptor<OAuth2TokenContext> tokenContextCaptor = ArgumentCaptor.forClass(OAuth2TokenContext.class);
		verify(this.tokenGenerator, times(2)).generate(tokenContextCaptor.capture());
		// tokenGenerator is first invoked for generating a new access token and then for
		// generating the refresh token
		List<OAuth2TokenContext> tokenContexts = tokenContextCaptor.getAllValues();
		assertThat(tokenContexts).hasSize(2);
		assertThat(tokenContexts.get(0).getAuthorization().getAccessToken().getToken().getTokenValue())
			.isEqualTo("access-token");
		assertThat(tokenContexts.get(1).getAuthorization().getAccessToken().getToken().getTokenValue())
			.isEqualTo("refreshed-access-token");
	}

	@Test
	public void authenticateWhenRequestedScopesAuthorizedThenAccessTokenIncludesScopes() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.scope("scope2")
			.scope("scope3")
			.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		given(this.authorizationService.findByToken(eq(authorization.getRefreshToken().getToken().getTokenValue()),
				eq(OAuth2TokenType.REFRESH_TOKEN)))
			.willReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		Set<String> authorizedScopes = authorization.getAuthorizedScopes();
		Set<String> requestedScopes = new HashSet<>(authorizedScopes);
		requestedScopes.remove("scope1");
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getRefreshToken().getToken().getTokenValue(), clientPrincipal, requestedScopes, null);

		OAuth2AccessTokenAuthenticationToken accessTokenAuthentication = (OAuth2AccessTokenAuthenticationToken) this.authenticationProvider
			.authenticate(authentication);

		assertThat(accessTokenAuthentication.getAccessToken().getScopes()).isEqualTo(requestedScopes);
	}

	@Test
	public void authenticateWhenRequestedScopesNotAuthorizedThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		given(this.authorizationService.findByToken(eq(authorization.getRefreshToken().getToken().getTokenValue()),
				eq(OAuth2TokenType.REFRESH_TOKEN)))
			.willReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		Set<String> authorizedScopes = authorization.getAuthorizedScopes();
		Set<String> requestedScopes = new HashSet<>(authorizedScopes);
		requestedScopes.add("unauthorized");
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getRefreshToken().getToken().getTokenValue(), clientPrincipal, requestedScopes, null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_SCOPE);
	}

	@Test
	public void authenticateWhenInvalidRefreshTokenThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken("invalid",
				clientPrincipal, null, null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}

	@Test
	public void authenticateWhenClientPrincipalNotOAuth2ClientAuthenticationTokenThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		TestingAuthenticationToken clientPrincipal = new TestingAuthenticationToken(registeredClient.getClientId(),
				registeredClient.getClientSecret());
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				"refresh-token", clientPrincipal, null, null);

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
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				"refresh-token", clientPrincipal, null, null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenRefreshTokenIssuedToAnotherClientThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		given(this.authorizationService.findByToken(eq(authorization.getRefreshToken().getToken().getTokenValue()),
				eq(OAuth2TokenType.REFRESH_TOKEN)))
			.willReturn(authorization);

		RegisteredClient registeredClient2 = TestRegisteredClients.registeredClient2().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient2,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient2.getClientSecret());
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getRefreshToken().getToken().getTokenValue(), clientPrincipal, null, null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}

	@Test
	public void authenticateWhenClientNotAuthorizedToRefreshTokenThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.authorizationGrantTypes((grantTypes) -> grantTypes.remove(AuthorizationGrantType.REFRESH_TOKEN))
			.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		given(this.authorizationService.findByToken(eq(authorization.getRefreshToken().getToken().getTokenValue()),
				eq(OAuth2TokenType.REFRESH_TOKEN)))
			.willReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getRefreshToken().getToken().getTokenValue(), clientPrincipal, null, null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
	}

	@Test
	public void authenticateWhenExpiredRefreshTokenThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		OAuth2RefreshToken expiredRefreshToken = new OAuth2RefreshToken("expired-refresh-token",
				Instant.now().minusSeconds(120), Instant.now().minusSeconds(60));
		authorization = OAuth2Authorization.from(authorization).token(expiredRefreshToken).build();
		given(this.authorizationService.findByToken(eq(authorization.getRefreshToken().getToken().getTokenValue()),
				eq(OAuth2TokenType.REFRESH_TOKEN)))
			.willReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getRefreshToken().getToken().getTokenValue(), clientPrincipal, null, null);

		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
			.isInstanceOf(OAuth2AuthenticationException.class)
			.extracting((ex) -> ((OAuth2AuthenticationException) ex).getError())
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
	}

	@Test
	public void authenticateWhenRevokedRefreshTokenThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", Instant.now().minusSeconds(120),
				Instant.now().plusSeconds(1000));
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.token(refreshToken, (metadata) -> metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true))
			.build();
		given(this.authorizationService.findByToken(eq(authorization.getRefreshToken().getToken().getTokenValue()),
				eq(OAuth2TokenType.REFRESH_TOKEN)))
			.willReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getRefreshToken().getToken().getTokenValue(), clientPrincipal, null, null);

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
		given(this.authorizationService.findByToken(eq(authorization.getRefreshToken().getToken().getTokenValue()),
				eq(OAuth2TokenType.REFRESH_TOKEN)))
			.willReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getRefreshToken().getToken().getTokenValue(), clientPrincipal, null, null);

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
	public void authenticateWhenRefreshTokenNotGeneratedThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.tokenSettings(TokenSettings.builder().reuseRefreshTokens(false).build())
			.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		given(this.authorizationService.findByToken(eq(authorization.getRefreshToken().getToken().getTokenValue()),
				eq(OAuth2TokenType.REFRESH_TOKEN)))
			.willReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getRefreshToken().getToken().getTokenValue(), clientPrincipal, null, null);

		willAnswer((answer) -> {
			OAuth2TokenContext context = answer.getArgument(0);
			if (OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
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
				assertThat(error.getDescription())
					.contains("The token generator failed to generate the refresh token.");
			});
	}

	@Test
	public void authenticateWhenIdTokenNotGeneratedThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scope(OidcScopes.OPENID).build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		given(this.authorizationService.findByToken(eq(authorization.getRefreshToken().getToken().getTokenValue()),
				eq(OAuth2TokenType.REFRESH_TOKEN)))
			.willReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getRefreshToken().getToken().getTokenValue(), clientPrincipal, null, null);

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
	public void authenticateWhenAccessTokenFormatReferenceThenAccessTokenGeneratorCalled() {
		// @formatter:off
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.tokenSettings(TokenSettings.builder()
						.accessTokenFormat(OAuth2TokenFormat.REFERENCE)
						.build())
				.build();
		// @formatter:on
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		given(this.authorizationService.findByToken(eq(authorization.getRefreshToken().getToken().getTokenValue()),
				eq(OAuth2TokenType.REFRESH_TOKEN)))
			.willReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				authorization.getRefreshToken().getToken().getTokenValue(), clientPrincipal, null, null);

		this.authenticationProvider.authenticate(authentication);

		verify(this.accessTokenCustomizer).customize(any());
	}

	private static Jwt createJwt(Set<String> scope) {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(1, ChronoUnit.HOURS);
		return Jwt.withTokenValue("refreshed-access-token")
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
