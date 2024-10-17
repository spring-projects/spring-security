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

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collections;
import java.util.function.Consumer;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.MockResponses;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link RestClientAuthorizationCodeTokenResponseClient}.
 *
 * @author Steve Riesenberg
 */
public class RestClientAuthorizationCodeTokenResponseClientTests {

	private RestClientAuthorizationCodeTokenResponseClient tokenResponseClient;

	private MockWebServer server;

	private ClientRegistration.Builder clientRegistration;

	private OAuth2AuthorizationExchange authorizationExchange;

	@BeforeEach
	public void setUp() throws IOException {
		this.tokenResponseClient = new RestClientAuthorizationCodeTokenResponseClient();
		this.server = new MockWebServer();
		this.server.start();
		String tokenUri = this.server.url("/oauth2/token").toString();
		this.clientRegistration = TestClientRegistrations.clientRegistration()
			.clientId("client-1")
			.clientSecret("secret")
			.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
			.tokenUri(tokenUri)
			.scope("read", "write");
		ClientRegistration clientRegistration = this.clientRegistration.build();
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
			.clientId("client-1")
			.state("state")
			.authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri())
			.redirectUri(clientRegistration.getRedirectUri())
			.scopes(clientRegistration.getScopes())
			.build();
		OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponse.success("code")
			.state("state")
			.redirectUri(clientRegistration.getRedirectUri())
			.build();
		this.authorizationExchange = new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse);
	}

	@AfterEach
	public void cleanUp() throws IOException {
		this.server.shutdown();
	}

	@Test
	public void setRestClientWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.tokenResponseClient.setRestClient(null))
				.withMessage("restClient cannot be null");
		// @formatter:on
	}

	@Test
	public void setHeadersConverterWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.tokenResponseClient.setHeadersConverter(null))
				.withMessage("headersConverter cannot be null");
		// @formatter:on
	}

	@Test
	public void addHeadersConverterWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.tokenResponseClient.addHeadersConverter(null))
				.withMessage("headersConverter cannot be null");
		// @formatter:on
	}

	@Test
	public void setParametersConverterWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.tokenResponseClient.setParametersConverter(null))
				.withMessage("parametersConverter cannot be null");
		// @formatter:on
	}

	@Test
	public void addParametersConverterWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.tokenResponseClient.addParametersConverter(null))
				.withMessage("parametersConverter cannot be null");
		// @formatter:on
	}

	@Test
	public void setParametersCustomizerWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.tokenResponseClient.setParametersCustomizer(null))
			.withMessage("parametersCustomizer cannot be null");
		// @formatter:on
	}

	@Test
	public void getTokenResponseWhenGrantRequestIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.tokenResponseClient.getTokenResponse(null))
				.withMessage("grantRequest cannot be null");
		// @formatter:on
	}

	@Test
	public void getTokenResponseWhenSuccessResponseThenReturnAccessTokenResponse() throws Exception {
		this.server.enqueue(MockResponses.json("access-token-response-read-write.json"));
		Instant expiresAtBefore = Instant.now().plusSeconds(3600);
		ClientRegistration clientRegistration = this.clientRegistration.build();
		OAuth2AuthorizationCodeGrantRequest grantRequest = new OAuth2AuthorizationCodeGrantRequest(clientRegistration,
				this.authorizationExchange);
		OAuth2AccessTokenResponse accessTokenResponse = this.tokenResponseClient.getTokenResponse(grantRequest);
		assertThat(accessTokenResponse).isNotNull();
		Instant expiresAtAfter = Instant.now().plusSeconds(3600);
		RecordedRequest recordedRequest = this.server.takeRequest();
		assertThat(recordedRequest.getMethod()).isEqualTo(HttpMethod.POST.toString());
		assertThat(recordedRequest.getHeader(HttpHeaders.ACCEPT)).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
		assertThat(recordedRequest.getHeader(HttpHeaders.CONTENT_TYPE))
			.isEqualTo(MediaType.APPLICATION_FORM_URLENCODED_VALUE);
		String formParameters = recordedRequest.getBody().readUtf8();
		// @formatter:off
		assertThat(formParameters).contains(
				param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue()),
				param(OAuth2ParameterNames.CODE, "code")
		);
		// @formatter:on
		assertThat(accessTokenResponse.getAccessToken().getTokenValue()).isEqualTo("access-token-1234");
		assertThat(accessTokenResponse.getAccessToken().getTokenType()).isEqualTo(OAuth2AccessToken.TokenType.BEARER);
		assertThat(accessTokenResponse.getAccessToken().getExpiresAt()).isBetween(expiresAtBefore, expiresAtAfter);
		assertThat(accessTokenResponse.getAccessToken().getScopes()).containsExactlyInAnyOrder("read", "write");
		assertThat(accessTokenResponse.getRefreshToken()).isNull();
	}

	@Test
	public void getTokenResponseWhenAuthenticationClientSecretBasicThenAuthorizationHeaderIsSent() throws Exception {
		this.server.enqueue(MockResponses.json("access-token-response.json"));
		ClientRegistration clientRegistration = this.clientRegistration.build();
		OAuth2AuthorizationCodeGrantRequest grantRequest = new OAuth2AuthorizationCodeGrantRequest(clientRegistration,
				this.authorizationExchange);
		this.tokenResponseClient.getTokenResponse(grantRequest);
		RecordedRequest recordedRequest = this.server.takeRequest();
		assertThat(recordedRequest.getHeader(HttpHeaders.AUTHORIZATION)).startsWith("Basic ");
	}

	@Test
	public void getTokenResponseWhenAuthenticationClientSecretPostThenFormParametersAreSent() throws Exception {
		this.server.enqueue(MockResponses.json("access-token-response.json"));
		ClientRegistration clientRegistration = this.clientRegistration
			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
			.build();
		OAuth2AuthorizationCodeGrantRequest grantRequest = new OAuth2AuthorizationCodeGrantRequest(clientRegistration,
				this.authorizationExchange);
		this.tokenResponseClient.getTokenResponse(grantRequest);
		RecordedRequest recordedRequest = this.server.takeRequest();
		String formParameters = recordedRequest.getBody().readUtf8();
		// @formatter:off
		assertThat(formParameters).contains(
				param(OAuth2ParameterNames.CLIENT_ID, "client-1"),
				param(OAuth2ParameterNames.CLIENT_SECRET, "secret")
		);
		// @formatter:on
	}

	@Test
	public void getTokenResponseWhenSuccessResponseAndNotBearerTokenTypeThenThrowOAuth2AuthorizationException() {
		this.server.enqueue(MockResponses.json("invalid-token-type-response.json"));
		ClientRegistration clientRegistration = this.clientRegistration.build();
		OAuth2AuthorizationCodeGrantRequest grantRequest = new OAuth2AuthorizationCodeGrantRequest(clientRegistration,
				this.authorizationExchange);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
				.isThrownBy(() -> this.tokenResponseClient.getTokenResponse(grantRequest))
				.satisfies((ex) -> assertThat(ex.getError().getErrorCode()).isEqualTo("invalid_token_response"))
				.withMessageContaining("[invalid_token_response] An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response")
				.havingRootCause().withMessage("tokenType cannot be null");
		// @formatter:on
	}

	@Test
	public void getTokenResponseWhenSuccessResponseIncludesScopeThenAccessTokenHasResponseScope() {
		this.server.enqueue(MockResponses.json("access-token-response-read.json"));
		ClientRegistration clientRegistration = this.clientRegistration.build();
		OAuth2AuthorizationCodeGrantRequest grantRequest = new OAuth2AuthorizationCodeGrantRequest(clientRegistration,
				this.authorizationExchange);
		OAuth2AccessTokenResponse accessTokenResponse = this.tokenResponseClient.getTokenResponse(grantRequest);
		assertThat(accessTokenResponse).isNotNull();
		assertThat(accessTokenResponse.getAccessToken().getScopes()).containsExactly("read");
	}

	@Test
	public void getTokenResponseWhenSuccessResponseDoesNotIncludeScopeThenAccessTokenHasNoScope() {
		this.server.enqueue(MockResponses.json("access-token-response.json"));
		ClientRegistration clientRegistration = this.clientRegistration.build();
		OAuth2AuthorizationCodeGrantRequest grantRequest = new OAuth2AuthorizationCodeGrantRequest(clientRegistration,
				this.authorizationExchange);
		OAuth2AccessTokenResponse accessTokenResponse = this.tokenResponseClient.getTokenResponse(grantRequest);
		assertThat(accessTokenResponse).isNotNull();
		assertThat(accessTokenResponse.getAccessToken().getScopes()).isEmpty();
	}

	@Test
	public void getTokenResponseWhenInvalidResponseThenThrowOAuth2AuthorizationException() {
		this.server.enqueue(new MockResponse().setResponseCode(301));
		ClientRegistration clientRegistration = this.clientRegistration.build();
		OAuth2AuthorizationCodeGrantRequest request = new OAuth2AuthorizationCodeGrantRequest(clientRegistration,
				this.authorizationExchange);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
				.isThrownBy(() -> this.tokenResponseClient.getTokenResponse(request))
				.satisfies((ex) -> assertThat(ex.getError().getErrorCode()).isEqualTo("invalid_token_response"))
				.withMessage("[invalid_token_response] Empty OAuth 2.0 Access Token Response");
		// @formatter:on
	}

	@Test
	public void getTokenResponseWhenServerErrorResponseThenThrowOAuth2AuthorizationException() {
		this.server.enqueue(MockResponses.json("server-error-response.json").setResponseCode(500));
		ClientRegistration clientRegistration = this.clientRegistration.build();
		OAuth2AuthorizationCodeGrantRequest request = new OAuth2AuthorizationCodeGrantRequest(clientRegistration,
				this.authorizationExchange);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
				.isThrownBy(() -> this.tokenResponseClient.getTokenResponse(request))
				.satisfies((ex) -> assertThat(ex.getError().getErrorCode()).isEqualTo("invalid_token_response"))
				.withMessageContaining("[invalid_token_response] An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response");
		// @formatter:on
	}

	@Test
	public void getTokenResponseWhenErrorResponseThenThrowOAuth2AuthorizationException() {
		this.server.enqueue(MockResponses.json("invalid-grant-response.json").setResponseCode(400));
		ClientRegistration clientRegistration = this.clientRegistration.build();
		OAuth2AuthorizationCodeGrantRequest request = new OAuth2AuthorizationCodeGrantRequest(clientRegistration,
				this.authorizationExchange);
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
				.isThrownBy(() -> this.tokenResponseClient.getTokenResponse(request))
				.satisfies((ex) -> assertThat(ex.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT))
				.withMessage("[invalid_grant] Invalid grant");
		// @formatter:on
	}

	@Test
	public void getTokenResponseWhenCustomClientAuthenticationMethodThenIllegalArgument() {
		ClientRegistration clientRegistration = this.clientRegistration
			.clientAuthenticationMethod(new ClientAuthenticationMethod("basic"))
			.build();
		OAuth2AuthorizationCodeGrantRequest grantRequest = new OAuth2AuthorizationCodeGrantRequest(clientRegistration,
				this.authorizationExchange);
		// @formatter:off
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> this.tokenResponseClient.getTokenResponse(grantRequest))
				.withMessageContaining("This class supports `client_secret_basic`, `client_secret_post`, and `none` by default.");
		// @formatter:on
	}

	@Test
	public void getTokenResponseWhenUnsupportedClientAuthenticationMethodThenIllegalArgument() {
		ClientRegistration clientRegistration = this.clientRegistration
			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
			.build();
		OAuth2AuthorizationCodeGrantRequest grantRequest = new OAuth2AuthorizationCodeGrantRequest(clientRegistration,
				this.authorizationExchange);
		// @formatter:off
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> this.tokenResponseClient.getTokenResponse(grantRequest))
				.withMessageContaining("This class supports `client_secret_basic`, `client_secret_post`, and `none` by default.");
		// @formatter:on
	}

	@Test
	public void getTokenResponseWhenHeadersConverterAddedThenCalled() throws Exception {
		this.server.enqueue(MockResponses.json("access-token-response.json"));
		ClientRegistration clientRegistration = this.clientRegistration.build();
		OAuth2AuthorizationCodeGrantRequest grantRequest = new OAuth2AuthorizationCodeGrantRequest(clientRegistration,
				this.authorizationExchange);
		Converter<OAuth2AuthorizationCodeGrantRequest, HttpHeaders> headersConverter = mock();
		HttpHeaders headers = new HttpHeaders();
		headers.put("custom-header-name", Collections.singletonList("custom-header-value"));
		given(headersConverter.convert(grantRequest)).willReturn(headers);
		this.tokenResponseClient.addHeadersConverter(headersConverter);
		this.tokenResponseClient.getTokenResponse(grantRequest);
		verify(headersConverter).convert(grantRequest);
		RecordedRequest recordedRequest = this.server.takeRequest();
		assertThat(recordedRequest.getHeader(HttpHeaders.AUTHORIZATION)).startsWith("Basic ");
		assertThat(recordedRequest.getHeader("custom-header-name")).isEqualTo("custom-header-value");
	}

	@Test
	public void getTokenResponseWhenHeadersConverterSetThenCalled() throws Exception {
		this.server.enqueue(MockResponses.json("access-token-response.json"));
		ClientRegistration clientRegistration = this.clientRegistration.build();
		OAuth2AuthorizationCodeGrantRequest grantRequest = new OAuth2AuthorizationCodeGrantRequest(clientRegistration,
				this.authorizationExchange);
		Converter<OAuth2AuthorizationCodeGrantRequest, HttpHeaders> headersConverter = mock();
		HttpHeaders headers = new HttpHeaders();
		headers.put("custom-header-name", Collections.singletonList("custom-header-value"));
		given(headersConverter.convert(grantRequest)).willReturn(headers);
		this.tokenResponseClient.setHeadersConverter(headersConverter);
		this.tokenResponseClient.getTokenResponse(grantRequest);
		verify(headersConverter).convert(grantRequest);
		RecordedRequest recordedRequest = this.server.takeRequest();
		assertThat(recordedRequest.getHeader(HttpHeaders.AUTHORIZATION)).isNull();
		assertThat(recordedRequest.getHeader("custom-header-name")).isEqualTo("custom-header-value");
	}

	@Test
	public void getTokenResponseWhenParametersConverterSetThenCalled() throws Exception {
		this.server.enqueue(MockResponses.json("access-token-response.json"));
		ClientRegistration clientRegistration = this.clientRegistration.build();
		OAuth2AuthorizationCodeGrantRequest grantRequest = new OAuth2AuthorizationCodeGrantRequest(clientRegistration,
				this.authorizationExchange);
		Converter<OAuth2AuthorizationCodeGrantRequest, MultiValueMap<String, String>> parametersConverter = mock();
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.add("custom-parameter-name", "custom-parameter-value");
		given(parametersConverter.convert(grantRequest)).willReturn(parameters);
		this.tokenResponseClient.setParametersConverter(parametersConverter);
		this.tokenResponseClient.getTokenResponse(grantRequest);
		verify(parametersConverter).convert(grantRequest);
		RecordedRequest recordedRequest = this.server.takeRequest();
		String formParameters = recordedRequest.getBody().readUtf8();
		assertThat(formParameters).contains(param("custom-parameter-name", "custom-parameter-value"));
	}

	@Test
	public void getTokenResponseWhenParametersConverterSetThenAbleToOverrideDefaultParameters() throws Exception {
		this.clientRegistration.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST);
		this.server.enqueue(MockResponses.json("access-token-response.json"));
		ClientRegistration clientRegistration = this.clientRegistration.build();
		OAuth2AuthorizationCodeGrantRequest grantRequest = new OAuth2AuthorizationCodeGrantRequest(clientRegistration,
				this.authorizationExchange);
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.GRANT_TYPE, "custom");
		parameters.set(OAuth2ParameterNames.CODE, "custom-code");
		parameters.set(OAuth2ParameterNames.REDIRECT_URI, "custom-uri");
		this.tokenResponseClient.setParametersConverter((authorizationGrantRequest) -> parameters);
		this.tokenResponseClient.getTokenResponse(grantRequest);
		RecordedRequest recordedRequest = this.server.takeRequest();
		String formParameters = recordedRequest.getBody().readUtf8();
		// @formatter:off
		assertThat(formParameters).contains(
				param(OAuth2ParameterNames.GRANT_TYPE, "custom"),
				param(OAuth2ParameterNames.CLIENT_ID, "client-1"),
				param(OAuth2ParameterNames.CODE, "custom-code"),
				param(OAuth2ParameterNames.REDIRECT_URI, "custom-uri")
		);
		// @formatter:on
	}

	@Test
	public void getTokenResponseWhenParametersConverterAddedThenCalled() throws Exception {
		this.server.enqueue(MockResponses.json("access-token-response.json"));
		ClientRegistration clientRegistration = this.clientRegistration.build();
		OAuth2AuthorizationCodeGrantRequest grantRequest = new OAuth2AuthorizationCodeGrantRequest(clientRegistration,
				this.authorizationExchange);
		Converter<OAuth2AuthorizationCodeGrantRequest, MultiValueMap<String, String>> parametersConverter = mock();
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.add("custom-parameter-name", "custom-parameter-value");
		given(parametersConverter.convert(grantRequest)).willReturn(parameters);
		this.tokenResponseClient.addParametersConverter(parametersConverter);
		this.tokenResponseClient.getTokenResponse(grantRequest);
		verify(parametersConverter).convert(grantRequest);
		RecordedRequest recordedRequest = this.server.takeRequest();
		String formParameters = recordedRequest.getBody().readUtf8();
		// @formatter:off
		assertThat(formParameters).contains(
				param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue()),
				param(OAuth2ParameterNames.CODE, "code"),
				param("custom-parameter-name", "custom-parameter-value")
		);
		// @formatter:on
	}

	@Test
	public void getTokenResponseWhenParametersCustomizerSetThenCalled() throws Exception {
		this.server.enqueue(MockResponses.json("access-token-response.json"));
		ClientRegistration clientRegistration = this.clientRegistration.build();
		OAuth2AuthorizationCodeGrantRequest grantRequest = new OAuth2AuthorizationCodeGrantRequest(clientRegistration,
				this.authorizationExchange);
		Consumer<MultiValueMap<String, String>> parametersCustomizer = mock();
		this.tokenResponseClient.setParametersCustomizer(parametersCustomizer);
		this.tokenResponseClient.getTokenResponse(grantRequest);
		verify(parametersCustomizer).accept(any());
	}

	@Test
	public void getTokenResponseWhenRestClientSetThenCalled() {
		this.server.enqueue(MockResponses.json("access-token-response.json"));
		RestClient restClient = RestClient.builder().messageConverters((messageConverters) -> {
			messageConverters.add(0, new FormHttpMessageConverter());
			messageConverters.add(1, new OAuth2AccessTokenResponseHttpMessageConverter());
		}).build();
		RestClient customClient = spy(restClient);
		this.tokenResponseClient.setRestClient(customClient);
		ClientRegistration clientRegistration = this.clientRegistration.build();
		OAuth2AuthorizationCodeGrantRequest grantRequest = new OAuth2AuthorizationCodeGrantRequest(clientRegistration,
				this.authorizationExchange);
		this.tokenResponseClient.getTokenResponse(grantRequest);
		verify(customClient).post();
	}

	private static String param(String parameterName, String parameterValue) {
		return "%s=%s".formatted(parameterName, URLEncoder.encode(parameterValue, StandardCharsets.UTF_8));
	}

}
