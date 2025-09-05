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
package org.springframework.security.oauth2.server.authorization.token;

import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.context.TestAuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link JwtGenerator}.
 *
 * @author Joe Grandja
 */
public class JwtGeneratorTests {

	private static final OAuth2TokenType ID_TOKEN_TOKEN_TYPE = new OAuth2TokenType(OidcParameterNames.ID_TOKEN);

	private JwtEncoder jwtEncoder;

	private OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer;

	private JwtGenerator jwtGenerator;

	private TestAuthorizationServerContext authorizationServerContext;

	@BeforeEach
	public void setUp() {
		this.jwtEncoder = mock(JwtEncoder.class);
		this.jwtCustomizer = mock(OAuth2TokenCustomizer.class);
		this.jwtGenerator = new JwtGenerator(this.jwtEncoder);
		this.jwtGenerator.setJwtCustomizer(this.jwtCustomizer);
		AuthorizationServerSettings authorizationServerSettings = AuthorizationServerSettings.builder()
			.issuer("https://provider.com")
			.build();
		this.authorizationServerContext = new TestAuthorizationServerContext(authorizationServerSettings, null);
	}

	@Test
	public void constructorWhenJwtEncoderNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new JwtGenerator(null)).isInstanceOf(IllegalArgumentException.class)
			.hasMessage("jwtEncoder cannot be null");
	}

	@Test
	public void setJwtCustomizerWhenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.jwtGenerator.setJwtCustomizer(null)).isInstanceOf(IllegalArgumentException.class)
			.hasMessage("jwtCustomizer cannot be null");
	}

	@Test
	public void generateWhenUnsupportedTokenTypeThenReturnNull() {
		// @formatter:off
		OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
				.tokenType(new OAuth2TokenType("unsupported_token_type"))
				.build();
		// @formatter:on

		assertThat(this.jwtGenerator.generate(tokenContext)).isNull();
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

		assertThat(this.jwtGenerator.generate(tokenContext)).isNull();
	}

	@Test
	public void generateWhenAccessTokenTypeThenReturnJwt() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		OAuth2AuthorizationCodeAuthenticationToken authentication = new OAuth2AuthorizationCodeAuthenticationToken(
				"code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

		// @formatter:off
		OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal(authorization.getAttribute(Principal.class.getName()))
				.authorizationServerContext(this.authorizationServerContext)
				.authorization(authorization)
				.authorizedScopes(authorization.getAuthorizedScopes())
				.tokenType(OAuth2TokenType.ACCESS_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrant(authentication)
				.build();
		// @formatter:on

		assertGeneratedTokenType(tokenContext);
	}

	@Test
	public void generateWhenIdTokenTypeAndAuthorizationCodeGrantThenReturnJwt() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient()
			.scope(OidcScopes.OPENID)
			.tokenSettings(TokenSettings.builder().idTokenSignatureAlgorithm(SignatureAlgorithm.ES256).build())
			.build();
		Map<String, Object> authenticationRequestAdditionalParameters = new HashMap<>();
		authenticationRequestAdditionalParameters.put(OidcParameterNames.NONCE, "nonce");
		OAuth2Authorization authorization = TestOAuth2Authorizations
			.authorization(registeredClient, authenticationRequestAdditionalParameters)
			.build();

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());
		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		OAuth2AuthorizationCodeAuthenticationToken authentication = new OAuth2AuthorizationCodeAuthenticationToken(
				"code", clientPrincipal, authorizationRequest.getRedirectUri(), null);

		Authentication principal = authorization.getAttribute(Principal.class.getName());
		SessionInformation sessionInformation = new SessionInformation(principal.getPrincipal(), "session1",
				Date.from(Instant.now().minus(2, ChronoUnit.HOURS)));

		// @formatter:off
		OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal(principal)
				.authorizationServerContext(this.authorizationServerContext)
				.authorization(authorization)
				.authorizedScopes(authorization.getAuthorizedScopes())
				.tokenType(ID_TOKEN_TOKEN_TYPE)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrant(authentication)
				.put(SessionInformation.class, sessionInformation)
				.build();
		// @formatter:on

		assertGeneratedTokenType(tokenContext);
	}

	// gh-1224
	@Test
	public void generateWhenIdTokenTypeAndRefreshTokenGrantThenReturnJwt() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scope(OidcScopes.OPENID).build();
		OidcIdToken idToken = OidcIdToken.withTokenValue("id-token")
			.issuer("https://provider.com")
			.subject("subject")
			.issuedAt(Instant.now())
			.expiresAt(Instant.now().plusSeconds(60))
			.claim("sid", "sessionId-1234")
			.claim(IdTokenClaimNames.AUTH_TIME, Date.from(Instant.now()))
			.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.token(idToken)
			.build();

		OAuth2RefreshToken refreshToken = authorization.getRefreshToken().getToken();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());

		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				refreshToken.getTokenValue(), clientPrincipal, null, null);

		Authentication principal = authorization.getAttribute(Principal.class.getName());

		// @formatter:off
		OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal(principal)
				.authorizationServerContext(this.authorizationServerContext)
				.authorization(authorization)
				.authorizedScopes(authorization.getAuthorizedScopes())
				.tokenType(ID_TOKEN_TOKEN_TYPE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrant(authentication)
				.build();
		// @formatter:on

		assertGeneratedTokenType(tokenContext);
	}

	// gh-1283
	@Test
	public void generateWhenIdTokenTypeWithoutSidAndRefreshTokenGrantThenReturnJwt() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().scope(OidcScopes.OPENID).build();
		OidcIdToken idToken = OidcIdToken.withTokenValue("id-token")
			.issuer("https://provider.com")
			.subject("subject")
			.issuedAt(Instant.now())
			.expiresAt(Instant.now().plusSeconds(60))
			.build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient)
			.token(idToken)
			.build();

		OAuth2RefreshToken refreshToken = authorization.getRefreshToken().getToken();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient,
				ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registeredClient.getClientSecret());

		OAuth2RefreshTokenAuthenticationToken authentication = new OAuth2RefreshTokenAuthenticationToken(
				refreshToken.getTokenValue(), clientPrincipal, null, null);

		Authentication principal = authorization.getAttribute(Principal.class.getName());

		// @formatter:off
		OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal(principal)
				.authorizationServerContext(this.authorizationServerContext)
				.authorization(authorization)
				.authorizedScopes(authorization.getAuthorizedScopes())
				.tokenType(ID_TOKEN_TOKEN_TYPE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrant(authentication)
				.build();
		// @formatter:on

		assertGeneratedTokenType(tokenContext);
	}

	private void assertGeneratedTokenType(OAuth2TokenContext tokenContext) {
		this.jwtGenerator.generate(tokenContext);

		ArgumentCaptor<JwtEncodingContext> jwtEncodingContextCaptor = ArgumentCaptor.forClass(JwtEncodingContext.class);
		verify(this.jwtCustomizer).customize(jwtEncodingContextCaptor.capture());

		JwtEncodingContext jwtEncodingContext = jwtEncodingContextCaptor.getValue();
		assertThat(jwtEncodingContext.getJwsHeader()).isNotNull();
		assertThat(jwtEncodingContext.getClaims()).isNotNull();
		assertThat(jwtEncodingContext.getRegisteredClient()).isEqualTo(tokenContext.getRegisteredClient());
		assertThat(jwtEncodingContext.<Authentication>getPrincipal()).isEqualTo(tokenContext.getPrincipal());
		assertThat(jwtEncodingContext.getAuthorization()).isEqualTo(tokenContext.getAuthorization());
		assertThat(jwtEncodingContext.getAuthorizedScopes()).isEqualTo(tokenContext.getAuthorizedScopes());
		assertThat(jwtEncodingContext.getTokenType()).isEqualTo(tokenContext.getTokenType());
		assertThat(jwtEncodingContext.getAuthorizationGrantType()).isEqualTo(tokenContext.getAuthorizationGrantType());
		assertThat(jwtEncodingContext.<Authentication>getAuthorizationGrant())
			.isEqualTo(tokenContext.getAuthorizationGrant());

		ArgumentCaptor<JwtEncoderParameters> jwtEncoderParametersCaptor = ArgumentCaptor
			.forClass(JwtEncoderParameters.class);
		verify(this.jwtEncoder).encode(jwtEncoderParametersCaptor.capture());

		JwsHeader jwsHeader = jwtEncoderParametersCaptor.getValue().getJwsHeader();
		if (OidcParameterNames.ID_TOKEN.equals(tokenContext.getTokenType().getValue())) {
			assertThat(jwsHeader.getAlgorithm())
				.isEqualTo(tokenContext.getRegisteredClient().getTokenSettings().getIdTokenSignatureAlgorithm());
		}
		else {
			assertThat(jwsHeader.getAlgorithm()).isEqualTo(SignatureAlgorithm.RS256);
		}

		JwtClaimsSet jwtClaimsSet = jwtEncoderParametersCaptor.getValue().getClaims();
		assertThat(jwtClaimsSet.getIssuer().toExternalForm())
			.isEqualTo(tokenContext.getAuthorizationServerContext().getIssuer());
		assertThat(jwtClaimsSet.getSubject()).isEqualTo(tokenContext.getAuthorization().getPrincipalName());
		assertThat(jwtClaimsSet.getAudience()).containsExactly(tokenContext.getRegisteredClient().getClientId());

		Instant issuedAt = Instant.now();
		Instant expiresAt;
		if (tokenContext.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
			expiresAt = issuedAt.plus(tokenContext.getRegisteredClient().getTokenSettings().getAccessTokenTimeToLive());
		}
		else {
			expiresAt = issuedAt.plus(30, ChronoUnit.MINUTES);
		}
		assertThat(jwtClaimsSet.getIssuedAt()).isBetween(issuedAt.minusSeconds(1), issuedAt.plusSeconds(1));
		assertThat(jwtClaimsSet.getExpiresAt()).isBetween(expiresAt.minusSeconds(1), expiresAt.plusSeconds(1));
		assertThat(jwtClaimsSet.getId()).isNotNull();

		if (tokenContext.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
			assertThat(jwtClaimsSet.getNotBefore()).isBetween(issuedAt.minusSeconds(1), issuedAt.plusSeconds(1));

			Set<String> scopes = jwtClaimsSet.getClaim(OAuth2ParameterNames.SCOPE);
			assertThat(scopes).isEqualTo(tokenContext.getAuthorizedScopes());
		}
		else {
			assertThat(jwtClaimsSet.<String>getClaim(IdTokenClaimNames.AZP))
				.isEqualTo(tokenContext.getRegisteredClient().getClientId());
			if (tokenContext.getAuthorizationGrantType().equals(AuthorizationGrantType.AUTHORIZATION_CODE)) {
				OAuth2AuthorizationRequest authorizationRequest = tokenContext.getAuthorization()
					.getAttribute(OAuth2AuthorizationRequest.class.getName());
				String nonce = (String) authorizationRequest.getAdditionalParameters().get(OidcParameterNames.NONCE);
				assertThat(jwtClaimsSet.<String>getClaim(IdTokenClaimNames.NONCE)).isEqualTo(nonce);

				SessionInformation sessionInformation = tokenContext.get(SessionInformation.class);
				assertThat(jwtClaimsSet.<String>getClaim("sid")).isEqualTo(sessionInformation.getSessionId());
				assertThat(jwtClaimsSet.<Date>getClaim(IdTokenClaimNames.AUTH_TIME))
					.isEqualTo(sessionInformation.getLastRequest());
			}
			else if (tokenContext.getAuthorizationGrantType().equals(AuthorizationGrantType.REFRESH_TOKEN)) {
				OidcIdToken currentIdToken = tokenContext.getAuthorization().getToken(OidcIdToken.class).getToken();
				assertThat(jwtClaimsSet.<String>getClaim("sid")).isEqualTo(currentIdToken.getClaim("sid"));
				assertThat(jwtClaimsSet.<Date>getClaim(IdTokenClaimNames.AUTH_TIME))
					.isEqualTo(currentIdToken.<Date>getClaim(IdTokenClaimNames.AUTH_TIME));
			}
		}
	}

}
