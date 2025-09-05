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
package org.springframework.security.oauth2.server.authorization.token;

import java.security.Principal;
import java.time.Instant;
import java.util.Collections;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.TestAuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link OAuth2AccessTokenGenerator}.
 *
 * @author Joe Grandja
 */
public class OAuth2AccessTokenGeneratorTests {

	private OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer;

	private OAuth2AccessTokenGenerator accessTokenGenerator;

	private AuthorizationServerContext authorizationServerContext;

	@BeforeEach
	public void setUp() {
		this.accessTokenCustomizer = mock(OAuth2TokenCustomizer.class);
		this.accessTokenGenerator = new OAuth2AccessTokenGenerator();
		this.accessTokenGenerator.setAccessTokenCustomizer(this.accessTokenCustomizer);
		AuthorizationServerSettings authorizationServerSettings = AuthorizationServerSettings.builder()
			.issuer("https://provider.com")
			.build();
		this.authorizationServerContext = new TestAuthorizationServerContext(authorizationServerSettings, null);
	}

	@Test
	public void setAccessTokenCustomizerWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.accessTokenGenerator.setAccessTokenCustomizer(null))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessage("accessTokenCustomizer cannot be null");
	}

	@Test
	public void generateWhenUnsupportedTokenTypeThenReturnNull() {
		// @formatter:off
		TokenSettings tokenSettings = TokenSettings.builder()
				.accessTokenFormat(OAuth2TokenFormat.REFERENCE)
				.build();
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.tokenSettings(tokenSettings)
				.build();
		OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.tokenType(new OAuth2TokenType("unsupported_token_type"))
				.build();
		// @formatter:on

		assertThat(this.accessTokenGenerator.generate(tokenContext)).isNull();
	}

	@Test
	public void generateWhenUnsupportedTokenFormatThenReturnNull() {
		// @formatter:off
		TokenSettings tokenSettings = TokenSettings.builder()
				.accessTokenFormat(new OAuth2TokenFormat("unsupported_token_format"))
				.build();
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.tokenSettings(tokenSettings)
				.build();
		OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.tokenType(OAuth2TokenType.ACCESS_TOKEN)
				.build();
		// @formatter:on

		assertThat(this.accessTokenGenerator.generate(tokenContext)).isNull();
	}

	@Test
	public void generateWhenReferenceAccessTokenTypeThenReturnAccessToken() {
		// @formatter:off
		TokenSettings tokenSettings = TokenSettings.builder()
				.accessTokenFormat(OAuth2TokenFormat.REFERENCE)
				.build();
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
				.tokenSettings(tokenSettings)
				.build();
		// @formatter:on
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		Authentication principal = authorization.getAttribute(Principal.class.getName());

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		OAuth2AuthorizationCodeAuthenticationToken authentication = new OAuth2AuthorizationCodeAuthenticationToken(
				"code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

		// @formatter:off
		OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal(principal)
				.authorizationServerContext(this.authorizationServerContext)
				.authorization(authorization)
				.authorizedScopes(authorization.getAuthorizedScopes())
				.tokenType(OAuth2TokenType.ACCESS_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrant(authentication)
				.build();
		// @formatter:on

		OAuth2AccessToken accessToken = this.accessTokenGenerator.generate(tokenContext);
		assertThat(accessToken).isNotNull();

		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt
			.plus(tokenContext.getRegisteredClient().getTokenSettings().getAccessTokenTimeToLive());
		assertThat(accessToken.getIssuedAt()).isBetween(issuedAt.minusSeconds(1), issuedAt.plusSeconds(1));
		assertThat(accessToken.getExpiresAt()).isBetween(expiresAt.minusSeconds(1), expiresAt.plusSeconds(1));
		assertThat(accessToken.getScopes()).isEqualTo(tokenContext.getAuthorizedScopes());

		assertThat(accessToken).isInstanceOf(ClaimAccessor.class);
		OAuth2TokenClaimAccessor accessTokenClaims = ((ClaimAccessor) accessToken)::getClaims;
		assertThat(accessTokenClaims.getClaims()).isNotEmpty();

		assertThat(accessTokenClaims.getIssuer().toExternalForm())
			.isEqualTo(tokenContext.getAuthorizationServerContext().getIssuer());
		assertThat(accessTokenClaims.getSubject()).isEqualTo(tokenContext.getPrincipal().getName());
		assertThat(accessTokenClaims.getAudience())
			.isEqualTo(Collections.singletonList(tokenContext.getRegisteredClient().getClientId()));
		assertThat(accessTokenClaims.getIssuedAt()).isBetween(issuedAt.minusSeconds(1), issuedAt.plusSeconds(1));
		assertThat(accessTokenClaims.getExpiresAt()).isBetween(expiresAt.minusSeconds(1), expiresAt.plusSeconds(1));
		assertThat(accessTokenClaims.getNotBefore()).isBetween(issuedAt.minusSeconds(1), issuedAt.plusSeconds(1));
		assertThat(accessTokenClaims.getId()).isNotNull();

		Set<String> scopes = accessTokenClaims.getClaim(OAuth2ParameterNames.SCOPE);
		assertThat(scopes).isEqualTo(tokenContext.getAuthorizedScopes());

		ArgumentCaptor<OAuth2TokenClaimsContext> tokenClaimsContextCaptor = ArgumentCaptor
			.forClass(OAuth2TokenClaimsContext.class);
		verify(this.accessTokenCustomizer).customize(tokenClaimsContextCaptor.capture());

		OAuth2TokenClaimsContext tokenClaimsContext = tokenClaimsContextCaptor.getValue();
		assertThat(tokenClaimsContext.getClaims()).isNotNull();
		assertThat(tokenClaimsContext.getRegisteredClient()).isEqualTo(tokenContext.getRegisteredClient());
		assertThat(tokenClaimsContext.<Authentication>getPrincipal()).isEqualTo(tokenContext.getPrincipal());
		assertThat(tokenClaimsContext.getAuthorizationServerContext())
			.isEqualTo(tokenContext.getAuthorizationServerContext());
		assertThat(tokenClaimsContext.getAuthorization()).isEqualTo(tokenContext.getAuthorization());
		assertThat(tokenClaimsContext.getAuthorizedScopes()).isEqualTo(tokenContext.getAuthorizedScopes());
		assertThat(tokenClaimsContext.getTokenType()).isEqualTo(tokenContext.getTokenType());
		assertThat(tokenClaimsContext.getAuthorizationGrantType()).isEqualTo(tokenContext.getAuthorizationGrantType());
		assertThat(tokenClaimsContext.<Authentication>getAuthorizationGrant())
			.isEqualTo(tokenContext.getAuthorizationGrant());
	}

}
