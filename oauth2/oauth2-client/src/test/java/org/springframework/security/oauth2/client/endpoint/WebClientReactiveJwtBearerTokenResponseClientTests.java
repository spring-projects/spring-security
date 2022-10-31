/*
 * Copyright 2002-2022 the original author or authors.
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

import java.util.Collections;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ReactiveHttpInputMessage;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AccessTokenResponses;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.TestJwts;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyExtractor;
import org.springframework.web.reactive.function.client.WebClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link WebClientReactiveJwtBearerTokenResponseClient}.
 *
 * @author Steve Riesenberg
 */
public class WebClientReactiveJwtBearerTokenResponseClientTests {

	// @formatter:off
	private static final String DEFAULT_ACCESS_TOKEN_RESPONSE = "{\n"
			+ "  \"access_token\": \"access-token-1234\",\n"
			+ "  \"token_type\": \"bearer\",\n"
			+ "  \"expires_in\": 3600\n"
			+ "}\n";
	// @formatter:on

	private WebClientReactiveJwtBearerTokenResponseClient client;

	private MockWebServer server;

	private ClientRegistration.Builder clientRegistration;

	private Jwt jwtAssertion;

	@BeforeEach
	public void setup() throws Exception {
		this.client = new WebClientReactiveJwtBearerTokenResponseClient();
		this.server = new MockWebServer();
		this.server.start();
		String tokenUri = this.server.url("/oauth2/token").toString();
		// @formatter:off
		this.clientRegistration = TestClientRegistrations.clientCredentials()
				.authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
				.tokenUri(tokenUri)
				.scope("read", "write");
		// @formatter:on
		this.jwtAssertion = TestJwts.jwt().build();
	}

	@AfterEach
	public void cleanup() throws Exception {
		this.server.shutdown();
	}

	@Test
	public void setWebClientWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.client.setWebClient(null))
				.withMessage("webClient cannot be null");
	}

	@Test
	public void setHeadersConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.client.setHeadersConverter(null))
				.withMessage("headersConverter cannot be null");
	}

	@Test
	public void addHeadersConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.client.addHeadersConverter(null))
				.withMessage("headersConverter cannot be null");
	}

	@Test
	public void setBodyExtractorWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.client.setBodyExtractor(null))
				.withMessage("bodyExtractor cannot be null");
	}

	@Test
	public void getTokenResponseWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.client.getTokenResponse(null))
				.withMessage("grantRequest cannot be null");
	}

	@Test
	public void getTokenResponseWhenInvalidResponseThenThrowOAuth2AuthorizationException() {
		ClientRegistration registration = this.clientRegistration.build();
		enqueueUnexpectedResponse();
		JwtBearerGrantRequest request = new JwtBearerGrantRequest(registration, this.jwtAssertion);
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
				.isThrownBy(() -> this.client.getTokenResponse(request).block())
				.satisfies((ex) -> assertThat(ex.getError().getErrorCode()).isEqualTo("invalid_token_response"))
				.withMessage("[invalid_token_response] Empty OAuth 2.0 Access Token Response");
	}

	@Test
	public void getTokenResponseWhenServerErrorResponseThenThrowOAuth2AuthorizationException() {
		ClientRegistration registration = this.clientRegistration.build();
		enqueueServerErrorResponse();
		JwtBearerGrantRequest request = new JwtBearerGrantRequest(registration, this.jwtAssertion);
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
				.isThrownBy(() -> this.client.getTokenResponse(request).block())
				.satisfies((ex) -> assertThat(ex.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.SERVER_ERROR))
				.withMessageContaining("[server_error]");
	}

	@Test
	public void getTokenResponseWhenErrorResponseThenThrowOAuth2AuthorizationException() {
		// @formatter:off
		String accessTokenResponse = "{\n"
				+ "  \"error\": \"invalid_grant\"\n"
				+ "}\n";
		// @formatter:on
		ClientRegistration registration = this.clientRegistration.build();
		enqueueJson(accessTokenResponse);
		JwtBearerGrantRequest request = new JwtBearerGrantRequest(registration, this.jwtAssertion);
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
				.isThrownBy(() -> this.client.getTokenResponse(request).block())
				.satisfies((ex) -> assertThat(ex.getError().getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT))
				.withMessageContaining("[invalid_grant]");
	}

	@Test
	public void getTokenResponseWhenResponseIsNotBearerTokenTypeThenThrowOAuth2AuthorizationException() {
		// @formatter:off
		String accessTokenResponse = "{\n"
				+ "  \"access_token\": \"access-token-1234\",\n"
				+ "  \"token_type\": \"not-bearer\",\n"
				+ "  \"expires_in\": 3600\n"
				+ "}\n";
		// @formatter:on
		ClientRegistration registration = this.clientRegistration.build();
		enqueueJson(accessTokenResponse);
		JwtBearerGrantRequest request = new JwtBearerGrantRequest(registration, this.jwtAssertion);
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
				.isThrownBy(() -> this.client.getTokenResponse(request).block())
				.satisfies((ex) -> assertThat(ex.getError().getErrorCode()).isEqualTo("invalid_token_response"))
				.withMessageContaining("[invalid_token_response] An error occurred parsing the Access Token response")
				.withMessageContaining("Unsupported token_type: not-bearer");
	}

	@Test
	public void getTokenResponseWhenWebClientSetThenCalled() {
		WebClient customClient = mock(WebClient.class);
		given(customClient.post()).willReturn(WebClient.builder().build().post());
		this.client.setWebClient(customClient);
		enqueueJson(DEFAULT_ACCESS_TOKEN_RESPONSE);
		ClientRegistration registration = this.clientRegistration.build();
		JwtBearerGrantRequest request = new JwtBearerGrantRequest(registration, this.jwtAssertion);
		this.client.getTokenResponse(request).block();
		verify(customClient).post();
	}

	@Test
	public void getTokenResponseWhenHeadersConverterSetThenCalled() throws Exception {
		ClientRegistration clientRegistration = this.clientRegistration.build();
		JwtBearerGrantRequest request = new JwtBearerGrantRequest(clientRegistration, this.jwtAssertion);
		Converter<JwtBearerGrantRequest, HttpHeaders> headersConverter = mock(Converter.class);
		HttpHeaders headers = new HttpHeaders();
		headers.setBasicAuth(clientRegistration.getClientId(), clientRegistration.getClientSecret());
		given(headersConverter.convert(request)).willReturn(headers);
		this.client.setHeadersConverter(headersConverter);
		enqueueJson(DEFAULT_ACCESS_TOKEN_RESPONSE);
		this.client.getTokenResponse(request).block();
		verify(headersConverter).convert(request);
		RecordedRequest actualRequest = this.server.takeRequest();
		assertThat(actualRequest.getHeader(HttpHeaders.AUTHORIZATION))
				.isEqualTo("Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=");
	}

	@Test
	public void getTokenResponseWhenHeadersConverterAddedThenCalled() throws Exception {
		ClientRegistration clientRegistration = this.clientRegistration.build();
		JwtBearerGrantRequest request = new JwtBearerGrantRequest(clientRegistration, this.jwtAssertion);
		Converter<JwtBearerGrantRequest, HttpHeaders> addedHeadersConverter = mock(Converter.class);
		HttpHeaders headers = new HttpHeaders();
		headers.put("custom-header-name", Collections.singletonList("custom-header-value"));
		given(addedHeadersConverter.convert(request)).willReturn(headers);
		this.client.addHeadersConverter(addedHeadersConverter);
		enqueueJson(DEFAULT_ACCESS_TOKEN_RESPONSE);
		this.client.getTokenResponse(request).block();
		verify(addedHeadersConverter).convert(request);
		RecordedRequest actualRequest = this.server.takeRequest();
		assertThat(actualRequest.getHeader(HttpHeaders.AUTHORIZATION))
				.isEqualTo("Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=");
		assertThat(actualRequest.getHeader("custom-header-name")).isEqualTo("custom-header-value");
	}

	@Test
	public void setParametersConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.client.setParametersConverter(null))
				.withMessage("parametersConverter cannot be null");
	}

	@Test
	public void addParametersConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.client.addParametersConverter(null))
				.withMessage("parametersConverter cannot be null");
	}

	@Test
	public void convertWhenParametersConverterAddedThenCalled() throws Exception {
		ClientRegistration clientRegistration = this.clientRegistration.build();
		JwtBearerGrantRequest request = new JwtBearerGrantRequest(clientRegistration, this.jwtAssertion);
		Converter<JwtBearerGrantRequest, MultiValueMap<String, String>> addedParametersConverter = mock(
				Converter.class);
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.add("custom-parameter-name", "custom-parameter-value");
		given(addedParametersConverter.convert(request)).willReturn(parameters);
		this.client.addParametersConverter(addedParametersConverter);
		enqueueJson(DEFAULT_ACCESS_TOKEN_RESPONSE);
		this.client.getTokenResponse(request).block();
		verify(addedParametersConverter).convert(request);
		RecordedRequest actualRequest = this.server.takeRequest();
		assertThat(actualRequest.getBody().readUtf8()).contains(
				"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer",
				"custom-parameter-name=custom-parameter-value");
	}

	@Test
	public void convertWhenParametersConverterSetThenCalled() throws Exception {
		ClientRegistration clientRegistration = this.clientRegistration.build();
		JwtBearerGrantRequest request = new JwtBearerGrantRequest(clientRegistration, this.jwtAssertion);
		Converter<JwtBearerGrantRequest, MultiValueMap<String, String>> parametersConverter = mock(Converter.class);
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.add("custom-parameter-name", "custom-parameter-value");
		given(parametersConverter.convert(request)).willReturn(parameters);
		this.client.setParametersConverter(parametersConverter);
		enqueueJson(DEFAULT_ACCESS_TOKEN_RESPONSE);
		this.client.getTokenResponse(request).block();
		verify(parametersConverter).convert(request);
		RecordedRequest actualRequest = this.server.takeRequest();
		assertThat(actualRequest.getBody().readUtf8()).contains("custom-parameter-name=custom-parameter-value");
	}

	@Test
	public void getTokenResponseWhenBodyExtractorSetThenCalled() {
		BodyExtractor<Mono<OAuth2AccessTokenResponse>, ReactiveHttpInputMessage> bodyExtractor = mock(
				BodyExtractor.class);
		OAuth2AccessTokenResponse response = TestOAuth2AccessTokenResponses.accessTokenResponse().build();
		given(bodyExtractor.extract(any(), any())).willReturn(Mono.just(response));
		ClientRegistration clientRegistration = this.clientRegistration.build();
		JwtBearerGrantRequest request = new JwtBearerGrantRequest(clientRegistration, this.jwtAssertion);
		this.client.setBodyExtractor(bodyExtractor);
		enqueueJson(DEFAULT_ACCESS_TOKEN_RESPONSE);
		this.client.getTokenResponse(request).block();
		verify(bodyExtractor).extract(any(), any());
	}

	@Test
	public void getTokenResponseWhenClientSecretBasicThenSuccess() throws Exception {
		// @formatter:off
		String accessTokenResponse = "{\n"
				+ "  \"access_token\": \"access-token-1234\",\n"
				+ "  \"token_type\": \"bearer\",\n"
				+ "  \"expires_in\": 3600,\n"
				+ "  \"scope\": \"read write\""
				+ "}\n";
		// @formatter:on
		ClientRegistration clientRegistration = this.clientRegistration.build();
		JwtBearerGrantRequest request = new JwtBearerGrantRequest(clientRegistration, this.jwtAssertion);
		enqueueJson(accessTokenResponse);
		OAuth2AccessTokenResponse response = this.client.getTokenResponse(request).block();
		assertThat(response).isNotNull();
		assertThat(response.getAccessToken().getScopes()).containsExactly("read", "write");
		RecordedRequest actualRequest = this.server.takeRequest();
		assertThat(actualRequest.getHeader(HttpHeaders.AUTHORIZATION))
				.isEqualTo("Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=");
		assertThat(actualRequest.getBody().readUtf8()).isEqualTo(
				"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&scope=read+write&assertion=token");
	}

	@Test
	public void getTokenResponseWhenClientSecretPostThenSuccess() throws Exception {
		// @formatter:off
		String accessTokenResponse = "{\n"
				+ "  \"access_token\": \"access-token-1234\",\n"
				+ "  \"token_type\": \"bearer\",\n"
				+ "  \"expires_in\": 3600,\n"
				+ "  \"scope\": \"read write\""
				+ "}\n";
		ClientRegistration clientRegistration = this.clientRegistration
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
				.build();
		// @formatter:on
		JwtBearerGrantRequest request = new JwtBearerGrantRequest(clientRegistration, this.jwtAssertion);
		enqueueJson(accessTokenResponse);
		OAuth2AccessTokenResponse response = this.client.getTokenResponse(request).block();
		assertThat(response).isNotNull();
		assertThat(response.getAccessToken().getScopes()).containsExactly("read", "write");
		RecordedRequest actualRequest = this.server.takeRequest();
		assertThat(actualRequest.getHeader(HttpHeaders.AUTHORIZATION)).isNull();
		assertThat(actualRequest.getBody().readUtf8()).isEqualTo(
				"grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&client_id=client-id&client_secret=client-secret&scope=read+write&assertion=token");
	}

	@Test
	public void getTokenResponseWhenResponseIncludesScopeThenAccessTokenHasResponseScope() throws Exception {
		// @formatter:off
		String accessTokenResponse = "{\n"
				+ "  \"access_token\": \"access-token-1234\",\n"
				+ "  \"token_type\": \"bearer\",\n"
				+ "  \"expires_in\": 3600,\n"
				+ "  \"scope\": \"read\"\n"
				+ "}\n";
		// @formatter:on
		ClientRegistration clientRegistration = this.clientRegistration.build();
		JwtBearerGrantRequest request = new JwtBearerGrantRequest(clientRegistration, this.jwtAssertion);
		enqueueJson(accessTokenResponse);
		OAuth2AccessTokenResponse response = this.client.getTokenResponse(request).block();
		assertThat(response).isNotNull();
		assertThat(response.getAccessToken().getScopes()).containsExactly("read");
	}

	@Test
	public void getTokenResponseWhenResponseDoesNotIncludeScopeThenReturnAccessTokenResponseWithNoScopes()
			throws Exception {
		ClientRegistration clientRegistration = this.clientRegistration.build();
		JwtBearerGrantRequest request = new JwtBearerGrantRequest(clientRegistration, this.jwtAssertion);
		enqueueJson(DEFAULT_ACCESS_TOKEN_RESPONSE);
		OAuth2AccessTokenResponse response = this.client.getTokenResponse(request).block();
		assertThat(response).isNotNull();
		assertThat(response.getAccessToken().getScopes()).isEmpty();
	}

	private void enqueueJson(String body) {
		MockResponse response = new MockResponse().setBody(body).setHeader(HttpHeaders.CONTENT_TYPE,
				MediaType.APPLICATION_JSON_VALUE);
		this.server.enqueue(response);
	}

	private void enqueueUnexpectedResponse() {
		// @formatter:off
		MockResponse response = new MockResponse()
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setResponseCode(301);
		// @formatter:on
		this.server.enqueue(response);
	}

	private void enqueueServerErrorResponse() {
		// @formatter:off
		MockResponse response = new MockResponse()
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setResponseCode(500)
				.setBody("{}");
		// @formatter:on
		this.server.enqueue(response);
	}

}
