/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.oauth2.client.endpoint;

import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.TestOAuth2RefreshTokens;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.TestJwts;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link DefaultOAuth2TokenRequestParametersConverter}.
 *
 * @author Steve Riesenberg
 */
public class DefaultOAuth2TokenRequestParametersConverterTests {

	private static final String ACCESS_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:access_token";

	private static final String JWT_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:jwt";

	private ClientRegistration.Builder clientRegistration;

	@BeforeEach
	public void setUp() {
		this.clientRegistration = TestClientRegistrations.clientRegistration()
			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
			.clientId("client-1")
			.clientSecret("secret")
			.scope("read", "write");
	}

	@Test
	public void convertWhenGrantRequestIsAuthorizationCodeThenParametersProvided() {
		ClientRegistration clientRegistration = this.clientRegistration
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.build();
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
			.clientId("client-1")
			.state("state")
			.authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri())
			.redirectUri(clientRegistration.getRedirectUri())
			.attributes(Map.of(PkceParameterNames.CODE_VERIFIER, "code-verifier"))
			.scopes(clientRegistration.getScopes())
			.build();
		OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponse.success("code")
			.state("state")
			.redirectUri(clientRegistration.getRedirectUri())
			.build();
		OAuth2AuthorizationExchange authorizationExchange = new OAuth2AuthorizationExchange(authorizationRequest,
				authorizationResponse);
		OAuth2AuthorizationCodeGrantRequest grantRequest = new OAuth2AuthorizationCodeGrantRequest(clientRegistration,
				authorizationExchange);
		// @formatter:off
		DefaultOAuth2TokenRequestParametersConverter<OAuth2AuthorizationCodeGrantRequest> parametersConverter =
			new DefaultOAuth2TokenRequestParametersConverter<>();
		// @formatter:on
		MultiValueMap<String, String> parameters = parametersConverter.convert(grantRequest);
		assertThat(parameters).hasSize(6);
		assertThat(parameters.get(OAuth2ParameterNames.GRANT_TYPE))
			.containsExactly(AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
		assertThat(parameters.get(OAuth2ParameterNames.CLIENT_ID)).containsExactly(clientRegistration.getClientId());
		assertThat(parameters.get(OAuth2ParameterNames.CLIENT_SECRET))
			.containsExactly(clientRegistration.getClientSecret());
		assertThat(parameters.get(OAuth2ParameterNames.CODE)).containsExactly(authorizationResponse.getCode());
		assertThat(parameters.get(OAuth2ParameterNames.REDIRECT_URI))
			.containsExactly(clientRegistration.getRedirectUri());
		assertThat(parameters.get(PkceParameterNames.CODE_VERIFIER))
			.containsExactly(authorizationRequest.<String>getAttribute(PkceParameterNames.CODE_VERIFIER));
	}

	@Test
	public void convertWhenGrantRequestIsClientCredentialsThenParametersProvided() {
		ClientRegistration clientRegistration = this.clientRegistration
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.build();
		OAuth2ClientCredentialsGrantRequest grantRequest = new OAuth2ClientCredentialsGrantRequest(clientRegistration);
		// @formatter:off
		DefaultOAuth2TokenRequestParametersConverter<OAuth2ClientCredentialsGrantRequest> parametersConverter =
			new DefaultOAuth2TokenRequestParametersConverter<>();
		// @formatter:on
		MultiValueMap<String, String> parameters = parametersConverter.convert(grantRequest);
		assertThat(parameters).hasSize(4);
		assertThat(parameters.get(OAuth2ParameterNames.GRANT_TYPE))
			.containsExactly(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue());
		assertThat(parameters.get(OAuth2ParameterNames.CLIENT_ID)).containsExactly(clientRegistration.getClientId());
		assertThat(parameters.get(OAuth2ParameterNames.CLIENT_SECRET))
			.containsExactly(clientRegistration.getClientSecret());
		assertThat(parameters.get(OAuth2ParameterNames.SCOPE))
			.containsExactly(StringUtils.collectionToDelimitedString(clientRegistration.getScopes(), " "));
	}

	@Test
	public void convertWhenGrantRequestIsRefreshTokenThenParametersProvided() {
		ClientRegistration clientRegistration = this.clientRegistration
			.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
			.build();
		OAuth2AccessToken accessToken = TestOAuth2AccessTokens.scopes("read", "write");
		OAuth2RefreshToken refreshToken = TestOAuth2RefreshTokens.refreshToken();
		OAuth2RefreshTokenGrantRequest grantRequest = new OAuth2RefreshTokenGrantRequest(clientRegistration,
				accessToken, refreshToken, clientRegistration.getScopes());
		// @formatter:off
		DefaultOAuth2TokenRequestParametersConverter<OAuth2RefreshTokenGrantRequest> parametersConverter =
			new DefaultOAuth2TokenRequestParametersConverter<>();
		// @formatter:on
		MultiValueMap<String, String> parameters = parametersConverter.convert(grantRequest);
		assertThat(parameters).hasSize(5);
		assertThat(parameters.get(OAuth2ParameterNames.GRANT_TYPE))
			.containsExactly(AuthorizationGrantType.REFRESH_TOKEN.getValue());
		assertThat(parameters.get(OAuth2ParameterNames.CLIENT_ID)).containsExactly(clientRegistration.getClientId());
		assertThat(parameters.get(OAuth2ParameterNames.CLIENT_SECRET))
			.containsExactly(clientRegistration.getClientSecret());
		assertThat(parameters.get(OAuth2ParameterNames.REFRESH_TOKEN)).containsExactly(refreshToken.getTokenValue());
		assertThat(parameters.get(OAuth2ParameterNames.SCOPE))
			.containsExactly(StringUtils.collectionToDelimitedString(clientRegistration.getScopes(), " "));
	}

	@Test
	public void convertWhenGrantRequestIsPasswordThenParametersProvided() {
		ClientRegistration clientRegistration = this.clientRegistration
			.authorizationGrantType(AuthorizationGrantType.PASSWORD)
			.build();
		OAuth2PasswordGrantRequest grantRequest = new OAuth2PasswordGrantRequest(clientRegistration, "user",
				"password");
		// @formatter:off
		DefaultOAuth2TokenRequestParametersConverter<OAuth2PasswordGrantRequest> parametersConverter =
			new DefaultOAuth2TokenRequestParametersConverter<>();
		// @formatter:on
		MultiValueMap<String, String> parameters = parametersConverter.convert(grantRequest);
		assertThat(parameters).hasSize(6);
		assertThat(parameters.get(OAuth2ParameterNames.GRANT_TYPE))
			.containsExactly(AuthorizationGrantType.PASSWORD.getValue());
		assertThat(parameters.get(OAuth2ParameterNames.CLIENT_ID)).containsExactly(clientRegistration.getClientId());
		assertThat(parameters.get(OAuth2ParameterNames.CLIENT_SECRET))
			.containsExactly(clientRegistration.getClientSecret());
		assertThat(parameters.get(OAuth2ParameterNames.USERNAME)).containsExactly(grantRequest.getUsername());
		assertThat(parameters.get(OAuth2ParameterNames.PASSWORD)).containsExactly(grantRequest.getPassword());
		assertThat(parameters.get(OAuth2ParameterNames.SCOPE))
			.containsExactly(StringUtils.collectionToDelimitedString(clientRegistration.getScopes(), " "));
	}

	@Test
	public void convertWhenGrantRequestIsJwtBearerThenParametersProvided() {
		ClientRegistration clientRegistration = this.clientRegistration
			.authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
			.build();
		Jwt jwt = TestJwts.jwt().build();
		JwtBearerGrantRequest grantRequest = new JwtBearerGrantRequest(clientRegistration, jwt);
		// @formatter:off
		DefaultOAuth2TokenRequestParametersConverter<JwtBearerGrantRequest> parametersConverter =
			new DefaultOAuth2TokenRequestParametersConverter<>();
		// @formatter:on
		MultiValueMap<String, String> parameters = parametersConverter.convert(grantRequest);
		assertThat(parameters).hasSize(5);
		assertThat(parameters.get(OAuth2ParameterNames.GRANT_TYPE))
			.containsExactly(AuthorizationGrantType.JWT_BEARER.getValue());
		assertThat(parameters.get(OAuth2ParameterNames.CLIENT_ID)).containsExactly(clientRegistration.getClientId());
		assertThat(parameters.get(OAuth2ParameterNames.CLIENT_SECRET))
			.containsExactly(clientRegistration.getClientSecret());
		assertThat(parameters.get(OAuth2ParameterNames.ASSERTION)).containsExactly(jwt.getTokenValue());
		assertThat(parameters.get(OAuth2ParameterNames.SCOPE))
			.containsExactly(StringUtils.collectionToDelimitedString(clientRegistration.getScopes(), " "));
	}

	@Test
	public void convertWhenGrantRequestIsTokenExchangeThenParametersProvided() {
		ClientRegistration clientRegistration = this.clientRegistration
			.authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
			.build();
		OAuth2Token subjectToken = TestOAuth2AccessTokens.scopes("read", "write");
		OAuth2Token actorToken = TestJwts.jwt().build();
		TokenExchangeGrantRequest grantRequest = new TokenExchangeGrantRequest(clientRegistration, subjectToken,
				actorToken);
		// @formatter:off
		DefaultOAuth2TokenRequestParametersConverter<TokenExchangeGrantRequest> parametersConverter =
			new DefaultOAuth2TokenRequestParametersConverter<>();
		// @formatter:on
		MultiValueMap<String, String> parameters = parametersConverter.convert(grantRequest);
		assertThat(parameters).hasSize(9);
		assertThat(parameters.get(OAuth2ParameterNames.GRANT_TYPE))
			.containsExactly(AuthorizationGrantType.TOKEN_EXCHANGE.getValue());
		assertThat(parameters.get(OAuth2ParameterNames.CLIENT_ID)).containsExactly(clientRegistration.getClientId());
		assertThat(parameters.get(OAuth2ParameterNames.CLIENT_SECRET))
			.containsExactly(clientRegistration.getClientSecret());
		assertThat(parameters.get(OAuth2ParameterNames.SCOPE))
			.containsExactly(StringUtils.collectionToDelimitedString(clientRegistration.getScopes(), " "));
		assertThat(parameters.get(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE)).containsExactly(ACCESS_TOKEN_TYPE_VALUE);
		assertThat(parameters.get(OAuth2ParameterNames.SUBJECT_TOKEN)).containsExactly(subjectToken.getTokenValue());
		assertThat(parameters.get(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE)).containsExactly(ACCESS_TOKEN_TYPE_VALUE);
		assertThat(parameters.get(OAuth2ParameterNames.ACTOR_TOKEN)).containsExactly(actorToken.getTokenValue());
		assertThat(parameters.get(OAuth2ParameterNames.ACTOR_TOKEN_TYPE)).containsExactly(JWT_TOKEN_TYPE_VALUE);
	}

}
