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

package org.springframework.security.oauth2.server.authorization.web.authentication;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

import org.junit.jupiter.api.Test;

import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link OAuth2AccessTokenResponseAuthenticationSuccessHandler}.
 *
 * @author Dmitriy Dubson
 */
public class OAuth2AccessTokenResponseAuthenticationSuccessHandlerTests {

	private final RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();

	private final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenHttpResponseConverter = new OAuth2AccessTokenResponseHttpMessageConverter();

	private final OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
			this.registeredClient, ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
			this.registeredClient.getClientSecret());

	private final OAuth2AccessTokenResponseAuthenticationSuccessHandler authenticationSuccessHandler = new OAuth2AccessTokenResponseAuthenticationSuccessHandler();

	@Test
	public void setAccessTokenResponseCustomizerWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> this.authenticationSuccessHandler.setAccessTokenResponseCustomizer(null))
				.withMessage("accessTokenResponseCustomizer cannot be null");
		// @formatter:on
	}

	@Test
	public void onAuthenticationSuccessWhenAuthenticationProvidedThenAccessTokenResponse() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(this.registeredClient).build();
		OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();
		OAuth2RefreshToken refreshToken = authorization.getRefreshToken().getToken();
		Map<String, Object> additionalParameters = Collections.singletonMap("param1", "value1");
		Authentication authentication = new OAuth2AccessTokenAuthenticationToken(this.registeredClient,
				this.clientPrincipal, accessToken, refreshToken, additionalParameters);

		this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, authentication);

		OAuth2AccessTokenResponse accessTokenResponse = readAccessTokenResponse(response);
		assertThat(accessTokenResponse.getAccessToken().getTokenValue()).isEqualTo(accessToken.getTokenValue());
		assertThat(accessTokenResponse.getAccessToken().getTokenType()).isEqualTo(accessToken.getTokenType());
		assertThat(accessTokenResponse.getAccessToken().getIssuedAt())
			.isBetween(accessToken.getIssuedAt().minusSeconds(1), accessToken.getIssuedAt().plusSeconds(1));
		assertThat(accessTokenResponse.getAccessToken().getExpiresAt())
			.isBetween(accessToken.getExpiresAt().minusSeconds(1), accessToken.getExpiresAt().plusSeconds(1));
		assertThat(accessTokenResponse.getRefreshToken()).isNotNull();
		assertThat(accessTokenResponse.getRefreshToken().getTokenValue()).isEqualTo(refreshToken.getTokenValue());
		assertThat(accessTokenResponse.getAdditionalParameters())
			.containsExactlyInAnyOrderEntriesOf(Map.of("param1", "value1"));
	}

	@Test
	public void onAuthenticationSuccessWhenInvalidAuthenticationTypeThenThrowOAuth2AuthenticationException() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		assertThatExceptionOfType(OAuth2AuthenticationException.class)
			.isThrownBy(() -> this.authenticationSuccessHandler.onAuthenticationSuccess(request, response,
					new TestingAuthenticationToken(this.clientPrincipal, null)))
			.extracting(OAuth2AuthenticationException::getError)
			.extracting("errorCode")
			.isEqualTo(OAuth2ErrorCodes.SERVER_ERROR);
	}

	@Test
	public void onAuthenticationSuccessWhenAccessTokenResponseCustomizerSetThenAccessTokenResponseCustomized()
			throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(this.registeredClient).build();
		OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();
		OAuth2RefreshToken refreshToken = authorization.getRefreshToken().getToken();
		Map<String, Object> additionalParameters = Collections.singletonMap("param1", "value1");
		Authentication authentication = new OAuth2AccessTokenAuthenticationToken(this.registeredClient,
				this.clientPrincipal, accessToken, refreshToken, additionalParameters);

		Consumer<OAuth2AccessTokenAuthenticationContext> accessTokenResponseCustomizer = (authenticationContext) -> {
			OAuth2AccessTokenAuthenticationToken accessTokenAuthentication = authenticationContext.getAuthentication();
			Map<String, Object> additionalParams = new HashMap<>(accessTokenAuthentication.getAdditionalParameters());
			additionalParams.put("authorization_id", authorization.getId());
			authenticationContext.getAccessTokenResponse().additionalParameters(additionalParams);
		};
		this.authenticationSuccessHandler.setAccessTokenResponseCustomizer(accessTokenResponseCustomizer);

		this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, authentication);

		OAuth2AccessTokenResponse accessTokenResponse = readAccessTokenResponse(response);
		assertThat(accessTokenResponse.getAccessToken().getTokenValue()).isEqualTo(accessToken.getTokenValue());
		assertThat(accessTokenResponse.getAccessToken().getTokenType()).isEqualTo(accessToken.getTokenType());
		assertThat(accessTokenResponse.getAccessToken().getIssuedAt())
			.isBetween(accessToken.getIssuedAt().minusSeconds(1), accessToken.getIssuedAt().plusSeconds(1));
		assertThat(accessTokenResponse.getAccessToken().getExpiresAt())
			.isBetween(accessToken.getExpiresAt().minusSeconds(1), accessToken.getExpiresAt().plusSeconds(1));
		assertThat(accessTokenResponse.getRefreshToken()).isNotNull();
		assertThat(accessTokenResponse.getRefreshToken().getTokenValue()).isEqualTo(refreshToken.getTokenValue());
		assertThat(accessTokenResponse.getAdditionalParameters())
			.containsExactlyInAnyOrderEntriesOf(Map.of("param1", "value1", "authorization_id", "id"));
	}

	private OAuth2AccessTokenResponse readAccessTokenResponse(MockHttpServletResponse response) throws Exception {
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(response.getContentAsByteArray(),
				HttpStatus.valueOf(response.getStatus()));
		return this.accessTokenHttpResponseConverter.read(OAuth2AccessTokenResponse.class, httpResponse);
	}

}
