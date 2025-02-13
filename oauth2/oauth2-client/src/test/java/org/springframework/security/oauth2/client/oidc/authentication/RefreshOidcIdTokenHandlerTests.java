/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.oauth2.client.oidc.authentication;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.RefreshTokenOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.event.OAuth2TokenRefreshedEvent;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class RefreshOidcIdTokenHandlerTests {

	private static final String EXISTING_ID_TOKEN_VALUE = "id-token-value";

	private static final String REFRESHED_ID_TOKEN_VALUE = "new-id-token-value";

	private static final String EXISTING_ACCESS_TOKEN_VALUE = "token-value";

	private static final String REFRESHED_ACCESS_TOKEN_VALUE = "new-token-value";

	private RefreshOidcIdTokenHandler handler;

	private RefreshTokenOAuth2AuthorizedClientProvider provider;

	private ClientRegistration clientRegistration;

	private OAuth2AuthorizedClient authorizedClient;

	private JwtDecoder jwtDecoder;

	private SecurityContext securityContext;

	private OidcIdToken existingIdToken;

	@BeforeEach
	void setUp() {
		this.handler = new RefreshOidcIdTokenHandler();

		this.clientRegistration = createClientRegistrationWithScopes(OidcScopes.OPENID);
		this.authorizedClient = createAuthorizedClient(this.clientRegistration);

		this.provider = mock(RefreshTokenOAuth2AuthorizedClientProvider.class);

		JwtDecoderFactory<ClientRegistration> jwtDecoderFactory = mock(JwtDecoderFactory.class);
		this.jwtDecoder = mock(JwtDecoder.class);
		SecurityContextHolderStrategy securityContextHolderStrategy = mock(SecurityContextHolderStrategy.class);
		this.securityContext = mock(SecurityContext.class);

		this.handler.setJwtDecoderFactory(jwtDecoderFactory);
		this.handler.setSecurityContextHolderStrategy(securityContextHolderStrategy);

		given(jwtDecoderFactory.createDecoder(any())).willReturn(this.jwtDecoder);
		given(securityContextHolderStrategy.createEmptyContext()).willReturn(this.securityContext);
		given(securityContextHolderStrategy.getContext()).willReturn(this.securityContext);

		Map<String, Object> claims = new HashMap<>();
		claims.put("sub", "subject");
		Jwt existingIdTokenJwt = new Jwt(EXISTING_ID_TOKEN_VALUE, Instant.now(), Instant.now().plusSeconds(3600),
				Map.of("alg", "RS256"), claims);
		Jwt refreshedIdTokenJwt = new Jwt(REFRESHED_ID_TOKEN_VALUE, Instant.now(), Instant.now().plusSeconds(3600),
				Map.of("alg", "RS256"), claims);

		this.existingIdToken = new OidcIdToken(existingIdTokenJwt.getTokenValue(), existingIdTokenJwt.getIssuedAt(),
				existingIdTokenJwt.getExpiresAt(), existingIdTokenJwt.getClaims());

		given(this.jwtDecoder.decode(existingIdTokenJwt.getTokenValue())).willReturn(existingIdTokenJwt);
		given(this.jwtDecoder.decode(refreshedIdTokenJwt.getTokenValue())).willReturn(refreshedIdTokenJwt);
	}

	@Test
	void handleEventWhenValidIdTokenThenUpdatesSecurityContext() {

		DefaultOidcUser existingUser = new DefaultOidcUser(AuthorityUtils.createAuthorityList("ROLE_USER"),
				this.existingIdToken);
		OAuth2AuthenticationToken existingAuth = new OAuth2AuthenticationToken(existingUser,
				existingUser.getAuthorities(), "registration-id");
		given(this.securityContext.getAuthentication()).willReturn(existingAuth);

		OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse
			.withToken(REFRESHED_ACCESS_TOKEN_VALUE)
			.tokenType(OAuth2AccessToken.TokenType.BEARER)
			.expiresIn(3600)
			.additionalParameters(Map.of(OidcParameterNames.ID_TOKEN, REFRESHED_ID_TOKEN_VALUE))
			.build();

		OAuth2TokenRefreshedEvent event = new OAuth2TokenRefreshedEvent(this.provider, this.authorizedClient,
				accessTokenResponse);
		this.handler.onApplicationEvent(event);

		ArgumentCaptor<OAuth2AuthenticationToken> authenticationCaptor = ArgumentCaptor
			.forClass(OAuth2AuthenticationToken.class);
		verify(this.securityContext).setAuthentication(authenticationCaptor.capture());

		OAuth2AuthenticationToken newAuthentication = authenticationCaptor.getValue();
		assertThat(newAuthentication.getPrincipal()).isInstanceOf(DefaultOidcUser.class);
		DefaultOidcUser newUser = (DefaultOidcUser) newAuthentication.getPrincipal();
		assertThat(newUser.getIdToken().getTokenValue()).isEqualTo(REFRESHED_ID_TOKEN_VALUE);
	}

	@Test
	void handleEventWhenAuthorizedClientIsNotOidcThenDoesNothing() {

		this.clientRegistration = createClientRegistrationWithScopes("read");
		this.authorizedClient = createAuthorizedClient(this.clientRegistration);

		OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse
			.withToken(REFRESHED_ACCESS_TOKEN_VALUE)
			.tokenType(OAuth2AccessToken.TokenType.BEARER)
			.expiresIn(3600)
			.additionalParameters(Map.of(OidcParameterNames.ID_TOKEN, REFRESHED_ID_TOKEN_VALUE))
			.build();

		OAuth2TokenRefreshedEvent event = new OAuth2TokenRefreshedEvent(this.provider, this.authorizedClient,
				accessTokenResponse);

		this.handler.onApplicationEvent(event);

		verify(this.securityContext, never()).setAuthentication(any());
		verify(this.jwtDecoder, never()).decode(any());
	}

	@Test
	void handleEventWhenAuthenticationNotOAuth2AuthenticationTokenThenDoesNothing() {

		given(this.securityContext.getAuthentication()).willReturn(mock(TestingAuthenticationToken.class));

		OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse
			.withToken(REFRESHED_ACCESS_TOKEN_VALUE)
			.tokenType(OAuth2AccessToken.TokenType.BEARER)
			.expiresIn(3600)
			.additionalParameters(Map.of(OidcParameterNames.ID_TOKEN, REFRESHED_ID_TOKEN_VALUE))
			.build();

		OAuth2TokenRefreshedEvent event = new OAuth2TokenRefreshedEvent(this.provider, this.authorizedClient,
				accessTokenResponse);

		this.handler.onApplicationEvent(event);

		verify(this.securityContext, never()).setAuthentication(any());
	}

	@Test
	void handleEventWhenNotOidcUserThenDoesNothing() {

		OAuth2AuthenticationToken existingAuth = new OAuth2AuthenticationToken(
				new DefaultOAuth2User(Collections.emptySet(),
						Collections.singletonMap("custom-attribute", "test-subject"), "custom-attribute"),
				AuthorityUtils.createAuthorityList("ROLE_USER"), "registration-id");
		given(this.securityContext.getAuthentication()).willReturn(existingAuth);

		OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse
			.withToken(REFRESHED_ACCESS_TOKEN_VALUE)
			.tokenType(OAuth2AccessToken.TokenType.BEARER)
			.expiresIn(3600)
			.additionalParameters(Map.of(OidcParameterNames.ID_TOKEN, REFRESHED_ID_TOKEN_VALUE))
			.build();

		OAuth2TokenRefreshedEvent event = new OAuth2TokenRefreshedEvent(this.provider, this.authorizedClient,
				accessTokenResponse);

		this.handler.onApplicationEvent(event);

		verify(this.securityContext, never()).setAuthentication(any());
	}

	@Test
	void handleEventWhenMissingIdTokenThenThrowsException() {

		DefaultOidcUser existingUser = new DefaultOidcUser(AuthorityUtils.createAuthorityList("ROLE_USER"),
				this.existingIdToken);
		OAuth2AuthenticationToken existingAuth = new OAuth2AuthenticationToken(existingUser,
				existingUser.getAuthorities(), "registration-id");
		given(this.securityContext.getAuthentication()).willReturn(existingAuth);

		OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse
			.withToken(REFRESHED_ACCESS_TOKEN_VALUE)
			.tokenType(OAuth2AccessToken.TokenType.BEARER)
			.expiresIn(3600)
			.additionalParameters(new HashMap<>()) // missing ID token
			.build();

		OAuth2TokenRefreshedEvent event = new OAuth2TokenRefreshedEvent(this.provider, this.authorizedClient,
				accessTokenResponse);

		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.handler.onApplicationEvent(event))
			.withMessageContaining("missing_id_token");
	}

	@Test
	void handleEventWhenInvalidIdTokenThenThrowsException() {

		DefaultOidcUser existingUser = new DefaultOidcUser(AuthorityUtils.createAuthorityList("ROLE_USER"),
				this.existingIdToken);
		OAuth2AuthenticationToken existingAuth = new OAuth2AuthenticationToken(existingUser,
				existingUser.getAuthorities(), "registration-id");
		given(this.securityContext.getAuthentication()).willReturn(existingAuth);

		given(this.jwtDecoder.decode(any())).willThrow(new JwtException("Invalid token"));

		OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse
			.withToken(REFRESHED_ACCESS_TOKEN_VALUE)
			.tokenType(OAuth2AccessToken.TokenType.BEARER)
			.expiresIn(3600)
			.additionalParameters(Map.of(OidcParameterNames.ID_TOKEN, "invalid-id-token"))
			.build();

		OAuth2TokenRefreshedEvent event = new OAuth2TokenRefreshedEvent(this.provider, this.authorizedClient,
				accessTokenResponse);

		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.handler.onApplicationEvent(event))
			.withMessageContaining("invalid_id_token");
	}

	private ClientRegistration createClientRegistrationWithScopes(String... scope) {
		return ClientRegistration.withRegistrationId("registration-id")
			.clientId("client-id")
			.clientSecret("secret")
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUri("http://localhost")
			.scope(scope)
			.authorizationUri("https://provider.com/oauth2/authorize")
			.tokenUri("https://provider.com/oauth2/token")
			.jwkSetUri("https://provider.com/jwk")
			.userInfoUri("https://provider.com/user")
			.build();
	}

	private static OAuth2AuthorizedClient createAuthorizedClient(ClientRegistration clientRegistration) {
		return new OAuth2AuthorizedClient(clientRegistration, "principal-name",
				new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, EXISTING_ACCESS_TOKEN_VALUE, Instant.now(),
						Instant.now().plusSeconds(3600)));
	}

}
