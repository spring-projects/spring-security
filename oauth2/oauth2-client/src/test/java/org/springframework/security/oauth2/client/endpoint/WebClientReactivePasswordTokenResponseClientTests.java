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

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collections;
import java.util.function.Consumer;
import java.util.function.Function;

import javax.crypto.spec.SecretKeySpec;

import com.nimbusds.jose.jwk.JWK;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ReactiveHttpInputMessage;
import org.springframework.security.oauth2.client.MockResponses;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AccessTokenResponses;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jose.TestKeys;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyExtractor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link WebClientReactivePasswordTokenResponseClient}.
 *
 * @author Joe Grandja
 */
public class WebClientReactivePasswordTokenResponseClientTests {

	private WebClientReactivePasswordTokenResponseClient tokenResponseClient = new WebClientReactivePasswordTokenResponseClient();

	private ClientRegistration.Builder clientRegistrationBuilder;

	private String username = "user1";

	private String password = "password";

	private MockWebServer server;

	@BeforeEach
	public void setup() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
		String tokenUri = this.server.url("/oauth2/token").toString();
		this.clientRegistrationBuilder = TestClientRegistrations.password().tokenUri(tokenUri);
	}

	@AfterEach
	public void cleanup() throws Exception {
		this.server.shutdown();
	}

	@Test
	public void setWebClientWhenClientIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.tokenResponseClient.setWebClient(null));
	}

	@Test
	public void getTokenResponseWhenRequestIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.tokenResponseClient.getTokenResponse(null).block());
	}

	@Test
	public void getTokenResponseWhenSuccessResponseDoesNotIncludeScopeThenReturnAccessTokenResponseWithNoScope()
			throws Exception {
		this.server.enqueue(MockResponses.json("access-token-response.json"));
		Instant expiresAtBefore = Instant.now().plusSeconds(3600);
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.build();
		OAuth2PasswordGrantRequest passwordGrantRequest = new OAuth2PasswordGrantRequest(clientRegistration,
				this.username, this.password);
		OAuth2AccessTokenResponse accessTokenResponse = this.tokenResponseClient.getTokenResponse(passwordGrantRequest)
			.block();
		Instant expiresAtAfter = Instant.now().plusSeconds(3600);
		RecordedRequest recordedRequest = this.server.takeRequest();
		assertThat(recordedRequest.getMethod()).isEqualTo(HttpMethod.POST.toString());
		assertThat(recordedRequest.getHeader(HttpHeaders.ACCEPT)).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
		assertThat(recordedRequest.getHeader(HttpHeaders.CONTENT_TYPE))
			.isEqualTo(MediaType.APPLICATION_FORM_URLENCODED_VALUE);
		String formParameters = recordedRequest.getBody().readUtf8();
		assertThat(formParameters).contains("grant_type=password");
		assertThat(formParameters).contains("username=user1");
		assertThat(formParameters).contains("password=password");
		assertThat(formParameters).contains("scope=read+write");
		assertThat(accessTokenResponse.getAccessToken().getTokenValue()).isEqualTo("access-token-1234");
		assertThat(accessTokenResponse.getAccessToken().getTokenType()).isEqualTo(OAuth2AccessToken.TokenType.BEARER);
		assertThat(accessTokenResponse.getAccessToken().getExpiresAt()).isBetween(expiresAtBefore, expiresAtAfter);
		assertThat(accessTokenResponse.getAccessToken().getScopes()).isEmpty();
		assertThat(accessTokenResponse.getRefreshToken()).isNull();
	}

	@Test
	public void getTokenResponseWhenSuccessResponseIncludesScopeThenReturnAccessTokenResponse() throws Exception {
		this.server.enqueue(MockResponses.json("access-token-response-read-write.json"));
		Instant expiresAtBefore = Instant.now().plusSeconds(3600);
		ClientRegistration clientRegistration = this.clientRegistrationBuilder.build();
		OAuth2PasswordGrantRequest passwordGrantRequest = new OAuth2PasswordGrantRequest(clientRegistration,
				this.username, this.password);
		OAuth2AccessTokenResponse accessTokenResponse = this.tokenResponseClient.getTokenResponse(passwordGrantRequest)
			.block();
		Instant expiresAtAfter = Instant.now().plusSeconds(3600);
		RecordedRequest recordedRequest = this.server.takeRequest();
		assertThat(recordedRequest.getMethod()).isEqualTo(HttpMethod.POST.toString());
		assertThat(recordedRequest.getHeader(HttpHeaders.ACCEPT)).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
		assertThat(recordedRequest.getHeader(HttpHeaders.CONTENT_TYPE))
			.isEqualTo(MediaType.APPLICATION_FORM_URLENCODED_VALUE);
		String formParameters = recordedRequest.getBody().readUtf8();
		assertThat(formParameters).contains("grant_type=password");
		assertThat(formParameters).contains("username=user1");
		assertThat(formParameters).contains("password=password");
		assertThat(formParameters).contains("scope=read+write");
		assertThat(accessTokenResponse.getAccessToken().getTokenValue()).isEqualTo("access-token-1234");
		assertThat(accessTokenResponse.getAccessToken().getTokenType()).isEqualTo(OAuth2AccessToken.TokenType.BEARER);
		assertThat(accessTokenResponse.getAccessToken().getExpiresAt()).isBetween(expiresAtBefore, expiresAtAfter);
		assertThat(accessTokenResponse.getAccessToken().getScopes())
			.containsExactly(clientRegistration.getScopes().toArray(new String[0]));
		assertThat(accessTokenResponse.getRefreshToken()).isNull();
	}

	@Test
	public void getTokenResponseWhenClientAuthenticationPostThenFormParametersAreSent() throws Exception {
		this.server.enqueue(MockResponses.json("access-token-response.json"));
		ClientRegistration clientRegistration = this.clientRegistrationBuilder
			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
			.build();
		OAuth2PasswordGrantRequest passwordGrantRequest = new OAuth2PasswordGrantRequest(clientRegistration,
				this.username, this.password);
		this.tokenResponseClient.getTokenResponse(passwordGrantRequest).block();
		RecordedRequest recordedRequest = this.server.takeRequest();
		assertThat(recordedRequest.getHeader(HttpHeaders.AUTHORIZATION)).isNull();
		String formParameters = recordedRequest.getBody().readUtf8();
		assertThat(formParameters).contains("client_id=client-id");
		assertThat(formParameters).contains("client_secret=client-secret");
	}

	@Test
	public void getTokenResponseWhenAuthenticationClientSecretJwtThenFormParametersAreSent() throws Exception {
		this.server.enqueue(MockResponses.json("access-token-response.json"));

		// @formatter:off
		ClientRegistration clientRegistration = this.clientRegistrationBuilder
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
				.clientSecret(TestKeys.DEFAULT_ENCODED_SECRET_KEY)
				.build();
		// @formatter:on

		// Configure Jwt client authentication converter
		SecretKeySpec secretKey = new SecretKeySpec(
				clientRegistration.getClientSecret().getBytes(StandardCharsets.UTF_8), "HmacSHA256");
		JWK jwk = TestJwks.jwk(secretKey).build();
		Function<ClientRegistration, JWK> jwkResolver = (registration) -> jwk;
		configureJwtClientAuthenticationConverter(jwkResolver);

		OAuth2PasswordGrantRequest passwordGrantRequest = new OAuth2PasswordGrantRequest(clientRegistration,
				this.username, this.password);
		this.tokenResponseClient.getTokenResponse(passwordGrantRequest).block();
		RecordedRequest actualRequest = this.server.takeRequest();
		assertThat(actualRequest.getHeader(HttpHeaders.AUTHORIZATION)).isNull();
		assertThat(actualRequest.getBody().readUtf8()).contains("grant_type=password",
				"client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer",
				"client_assertion=");
	}

	@Test
	public void getTokenResponseWhenAuthenticationPrivateKeyJwtThenFormParametersAreSent() throws Exception {
		this.server.enqueue(MockResponses.json("access-token-response.json"));

		// @formatter:off
		ClientRegistration clientRegistration = this.clientRegistrationBuilder
				.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
				.build();
		// @formatter:on

		// Configure Jwt client authentication converter
		JWK jwk = TestJwks.DEFAULT_RSA_JWK;
		Function<ClientRegistration, JWK> jwkResolver = (registration) -> jwk;
		configureJwtClientAuthenticationConverter(jwkResolver);

		OAuth2PasswordGrantRequest passwordGrantRequest = new OAuth2PasswordGrantRequest(clientRegistration,
				this.username, this.password);
		this.tokenResponseClient.getTokenResponse(passwordGrantRequest).block();
		RecordedRequest actualRequest = this.server.takeRequest();
		assertThat(actualRequest.getHeader(HttpHeaders.AUTHORIZATION)).isNull();
		assertThat(actualRequest.getBody().readUtf8()).contains("grant_type=password",
				"client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer",
				"client_assertion=");
	}

	private void configureJwtClientAuthenticationConverter(Function<ClientRegistration, JWK> jwkResolver) {
		NimbusJwtClientAuthenticationParametersConverter<OAuth2PasswordGrantRequest> jwtClientAuthenticationConverter = new NimbusJwtClientAuthenticationParametersConverter<>(
				jwkResolver);
		this.tokenResponseClient.addParametersConverter(jwtClientAuthenticationConverter);
	}

	@Test
	public void getTokenResponseWhenSuccessResponseAndNotBearerTokenTypeThenThrowOAuth2AuthorizationException() {
		this.server.enqueue(MockResponses.json("invalid-token-type-response.json"));
		OAuth2PasswordGrantRequest passwordGrantRequest = new OAuth2PasswordGrantRequest(
				this.clientRegistrationBuilder.build(), this.username, this.password);
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
			.isThrownBy(() -> this.tokenResponseClient.getTokenResponse(passwordGrantRequest).block())
			.satisfies((ex) -> assertThat(ex.getError().getErrorCode()).isEqualTo("invalid_token_response"))
			.withMessageContaining("[invalid_token_response]")
			.withMessageContaining("An error occurred parsing the Access Token response")
			.withCauseInstanceOf(Throwable.class);
	}

	@Test
	public void getTokenResponseWhenSuccessResponseIncludesScopeThenAccessTokenHasResponseScope() throws Exception {
		this.server.enqueue(MockResponses.json("access-token-response-read.json"));
		OAuth2PasswordGrantRequest passwordGrantRequest = new OAuth2PasswordGrantRequest(
				this.clientRegistrationBuilder.build(), this.username, this.password);
		OAuth2AccessTokenResponse accessTokenResponse = this.tokenResponseClient.getTokenResponse(passwordGrantRequest)
			.block();
		RecordedRequest recordedRequest = this.server.takeRequest();
		String formParameters = recordedRequest.getBody().readUtf8();
		assertThat(formParameters).contains("scope=read");
		assertThat(accessTokenResponse.getAccessToken().getScopes()).containsExactly("read");
	}

	@Test
	public void getTokenResponseWhenErrorResponseThenThrowOAuth2AuthorizationException() {
		this.server.enqueue(MockResponses.json("unauthorized-client-response.json").setResponseCode(400));
		OAuth2PasswordGrantRequest passwordGrantRequest = new OAuth2PasswordGrantRequest(
				this.clientRegistrationBuilder.build(), this.username, this.password);
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
			.isThrownBy(() -> this.tokenResponseClient.getTokenResponse(passwordGrantRequest).block())
			.satisfies((ex) -> assertThat(ex.getError().getErrorCode()).isEqualTo("unauthorized_client"))
			.withMessageContaining("[unauthorized_client]");
	}

	@Test
	public void getTokenResponseWhenServerErrorResponseThenThrowOAuth2AuthorizationException() {
		this.server.enqueue(new MockResponse().setResponseCode(500));
		OAuth2PasswordGrantRequest passwordGrantRequest = new OAuth2PasswordGrantRequest(
				this.clientRegistrationBuilder.build(), this.username, this.password);
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
			.isThrownBy(() -> this.tokenResponseClient.getTokenResponse(passwordGrantRequest).block())
			.satisfies((ex) -> assertThat(ex.getError().getErrorCode()).isEqualTo("invalid_token_response"))
			.withMessageContaining("[invalid_token_response]")
			.withMessageContaining("Empty OAuth 2.0 Access Token Response");
	}

	// gh-10130
	@Test
	public void setHeadersConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.tokenResponseClient.setHeadersConverter(null))
			.withMessage("headersConverter cannot be null");
	}

	// gh-10130
	@Test
	public void addHeadersConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.tokenResponseClient.addHeadersConverter(null))
			.withMessage("headersConverter cannot be null");
	}

	// gh-10130
	@Test
	public void convertWhenHeadersConverterAddedThenCalled() throws Exception {
		OAuth2PasswordGrantRequest request = new OAuth2PasswordGrantRequest(this.clientRegistrationBuilder.build(),
				this.username, this.password);
		Converter<OAuth2PasswordGrantRequest, HttpHeaders> addedHeadersConverter = mock();
		HttpHeaders headers = new HttpHeaders();
		headers.put("custom-header-name", Collections.singletonList("custom-header-value"));
		given(addedHeadersConverter.convert(request)).willReturn(headers);
		this.tokenResponseClient.addHeadersConverter(addedHeadersConverter);
		this.server.enqueue(MockResponses.json("access-token-response.json"));
		this.tokenResponseClient.getTokenResponse(request).block();
		verify(addedHeadersConverter).convert(request);
		RecordedRequest actualRequest = this.server.takeRequest();
		assertThat(actualRequest.getHeader(HttpHeaders.AUTHORIZATION))
			.isEqualTo("Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=");
		assertThat(actualRequest.getHeader("custom-header-name")).isEqualTo("custom-header-value");
	}

	// gh-10130
	@Test
	public void convertWhenHeadersConverterSetThenCalled() throws Exception {
		OAuth2PasswordGrantRequest request = new OAuth2PasswordGrantRequest(this.clientRegistrationBuilder.build(),
				this.username, this.password);
		ClientRegistration clientRegistration = request.getClientRegistration();
		Converter<OAuth2PasswordGrantRequest, HttpHeaders> headersConverter = mock();
		HttpHeaders headers = new HttpHeaders();
		headers.setBasicAuth(clientRegistration.getClientId(), clientRegistration.getClientSecret());
		given(headersConverter.convert(request)).willReturn(headers);
		this.tokenResponseClient.setHeadersConverter(headersConverter);
		this.server.enqueue(MockResponses.json("access-token-response.json"));
		this.tokenResponseClient.getTokenResponse(request).block();
		verify(headersConverter).convert(request);
		RecordedRequest actualRequest = this.server.takeRequest();
		assertThat(actualRequest.getHeader(HttpHeaders.AUTHORIZATION))
			.isEqualTo("Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=");
	}

	@Test
	public void setParametersConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.tokenResponseClient.setParametersConverter(null))
			.withMessage("parametersConverter cannot be null");
	}

	@Test
	public void addParametersConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.tokenResponseClient.addParametersConverter(null))
			.withMessage("parametersConverter cannot be null");
	}

	@Test
	public void getTokenResponseWhenParametersConverterAddedThenCalled() throws Exception {
		OAuth2PasswordGrantRequest request = new OAuth2PasswordGrantRequest(this.clientRegistrationBuilder.build(),
				this.username, this.password);
		Converter<OAuth2PasswordGrantRequest, MultiValueMap<String, String>> addedParametersConverter = mock();
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.add("custom-parameter-name", "custom-parameter-value");
		given(addedParametersConverter.convert(request)).willReturn(parameters);
		this.tokenResponseClient.addParametersConverter(addedParametersConverter);
		this.server.enqueue(MockResponses.json("access-token-response.json"));
		this.tokenResponseClient.getTokenResponse(request).block();
		verify(addedParametersConverter).convert(request);
		RecordedRequest actualRequest = this.server.takeRequest();
		String formParameters = actualRequest.getBody().readUtf8();
		// @formatter:off
		assertThat(formParameters).contains(
				param(OAuth2ParameterNames.GRANT_TYPE, "password"),
				param("custom-parameter-name", "custom-parameter-value")
		);
		// @formatter:on
	}

	@Test
	public void getTokenResponseWhenParametersConverterSetThenCalled() throws Exception {
		OAuth2PasswordGrantRequest request = new OAuth2PasswordGrantRequest(this.clientRegistrationBuilder.build(),
				this.username, this.password);
		Converter<OAuth2PasswordGrantRequest, MultiValueMap<String, String>> parametersConverter = mock();
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.add("custom-parameter-name", "custom-parameter-value");
		given(parametersConverter.convert(request)).willReturn(parameters);
		this.tokenResponseClient.setParametersConverter(parametersConverter);
		this.server.enqueue(MockResponses.json("access-token-response.json"));
		this.tokenResponseClient.getTokenResponse(request).block();
		verify(parametersConverter).convert(request);
		RecordedRequest actualRequest = this.server.takeRequest();
		assertThat(actualRequest.getBody().readUtf8()).contains("custom-parameter-name=custom-parameter-value");
	}

	@Test
	public void getTokenResponseWhenParametersConverterSetThenAbleToOverrideDefaultParameters() throws Exception {
		this.clientRegistrationBuilder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST);
		OAuth2PasswordGrantRequest request = new OAuth2PasswordGrantRequest(this.clientRegistrationBuilder.build(),
				this.username, this.password);
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.GRANT_TYPE, "custom");
		parameters.set(OAuth2ParameterNames.USERNAME, "user");
		parameters.set(OAuth2ParameterNames.PASSWORD, "password");
		parameters.set(OAuth2ParameterNames.SCOPE, "one two");
		this.tokenResponseClient.setParametersConverter((grantRequest) -> parameters);
		this.server.enqueue(MockResponses.json("access-token-response.json"));
		this.tokenResponseClient.getTokenResponse(request).block();
		String formParameters = this.server.takeRequest().getBody().readUtf8();
		// @formatter:off
		assertThat(formParameters).contains(
				param(OAuth2ParameterNames.GRANT_TYPE, "custom"),
				param(OAuth2ParameterNames.CLIENT_ID, "client-id"),
				param(OAuth2ParameterNames.SCOPE, "one two"),
				param(OAuth2ParameterNames.USERNAME, "user"),
				param(OAuth2ParameterNames.PASSWORD, "password")
		);
		// @formatter:on
	}

	@Test
	public void getTokenResponseWhenParametersCustomizerSetThenCalled() throws Exception {
		this.server.enqueue(MockResponses.json("access-token-response.json"));
		OAuth2PasswordGrantRequest request = new OAuth2PasswordGrantRequest(this.clientRegistrationBuilder.build(),
				this.username, this.password);
		Consumer<MultiValueMap<String, String>> parametersCustomizer = mock();
		this.tokenResponseClient.setParametersCustomizer(parametersCustomizer);
		this.tokenResponseClient.getTokenResponse(request).block();
		verify(parametersCustomizer).accept(any());
	}

	// gh-10260
	@Test
	public void getTokenResponseWhenSuccessCustomResponseThenReturnAccessTokenResponse() {

		WebClientReactivePasswordTokenResponseClient customClient = new WebClientReactivePasswordTokenResponseClient();

		BodyExtractor<Mono<OAuth2AccessTokenResponse>, ReactiveHttpInputMessage> extractor = mock();
		OAuth2AccessTokenResponse response = TestOAuth2AccessTokenResponses.accessTokenResponse().build();
		given(extractor.extract(any(), any())).willReturn(Mono.just(response));

		customClient.setBodyExtractor(extractor);

		ClientRegistration clientRegistration = this.clientRegistrationBuilder.build();
		OAuth2PasswordGrantRequest passwordGrantRequest = new OAuth2PasswordGrantRequest(clientRegistration,
				this.username, this.password);

		this.server.enqueue(MockResponses.json("access-token-response.json"));

		OAuth2AccessTokenResponse accessTokenResponse = customClient.getTokenResponse(passwordGrantRequest).block();
		assertThat(accessTokenResponse.getAccessToken()).isNotNull();

	}

	private static String param(String parameterName, String parameterValue) {
		return "%s=%s".formatted(parameterName, URLEncoder.encode(parameterValue, StandardCharsets.UTF_8));
	}

}
