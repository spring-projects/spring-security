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

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
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
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ReactiveHttpInputMessage;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AccessTokenResponses;
import org.springframework.security.oauth2.jose.TestJwks;
import org.springframework.security.oauth2.jose.TestKeys;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyExtractor;
import org.springframework.web.reactive.function.client.WebClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 * @since 5.1
 */
public class WebClientReactiveAuthorizationCodeTokenResponseClientTests {

	private ClientRegistration.Builder clientRegistration;

	private WebClientReactiveAuthorizationCodeTokenResponseClient tokenResponseClient = new WebClientReactiveAuthorizationCodeTokenResponseClient();

	private MockWebServer server;

	@BeforeEach
	public void setup() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
		String tokenUri = this.server.url("/oauth2/token").toString();
		this.clientRegistration = TestClientRegistrations.clientRegistration().tokenUri(tokenUri);
	}

	@AfterEach
	public void cleanup() throws Exception {
		this.server.shutdown();
	}

	@Test
	public void getTokenResponseWhenSuccessResponseThenReturnAccessTokenResponse() throws Exception {
		// @formatter:off
		String accessTokenSuccessResponse = "{\n"
			+ "   \"access_token\": \"access-token-1234\",\n"
			+ "   \"token_type\": \"bearer\",\n"
			+ "   \"expires_in\": \"3600\",\n"
			+ "   \"scope\": \"openid profile\",\n"
			+ "   \"refresh_token\": \"refresh-token-1234\",\n"
			+ "   \"custom_parameter_1\": \"custom-value-1\",\n"
			+ "   \"custom_parameter_2\": \"custom-value-2\"\n"
			+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));
		Instant expiresAtBefore = Instant.now().plusSeconds(3600);
		OAuth2AccessTokenResponse accessTokenResponse = this.tokenResponseClient
				.getTokenResponse(authorizationCodeGrantRequest()).block();
		String body = this.server.takeRequest().getBody().readUtf8();
		assertThat(body).isEqualTo(
				"grant_type=authorization_code&code=code&redirect_uri=%7BbaseUrl%7D%2F%7Baction%7D%2Foauth2%2Fcode%2F%7BregistrationId%7D");
		Instant expiresAtAfter = Instant.now().plusSeconds(3600);
		assertThat(accessTokenResponse.getAccessToken().getTokenValue()).isEqualTo("access-token-1234");
		assertThat(accessTokenResponse.getAccessToken().getTokenType()).isEqualTo(OAuth2AccessToken.TokenType.BEARER);
		assertThat(accessTokenResponse.getAccessToken().getExpiresAt()).isBetween(expiresAtBefore, expiresAtAfter);
		assertThat(accessTokenResponse.getAccessToken().getScopes()).containsExactly("openid", "profile");
		assertThat(accessTokenResponse.getRefreshToken().getTokenValue()).isEqualTo("refresh-token-1234");
		assertThat(accessTokenResponse.getAdditionalParameters().size()).isEqualTo(2);
		assertThat(accessTokenResponse.getAdditionalParameters()).containsEntry("custom_parameter_1", "custom-value-1");
		assertThat(accessTokenResponse.getAdditionalParameters()).containsEntry("custom_parameter_2", "custom-value-2");
	}

	@Test
	public void getTokenResponseWhenAuthenticationClientSecretJwtThenFormParametersAreSent() throws Exception {
		// @formatter:off
		String accessTokenSuccessResponse = "{\n"
				+ "	  \"access_token\": \"access-token-1234\",\n"
				+ "   \"token_type\": \"bearer\",\n"
				+ "   \"expires_in\": \"3600\"\n"
				+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));

		// @formatter:off
		ClientRegistration clientRegistration = this.clientRegistration
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

		this.tokenResponseClient.getTokenResponse(authorizationCodeGrantRequest(clientRegistration)).block();
		RecordedRequest actualRequest = this.server.takeRequest();
		assertThat(actualRequest.getHeader(HttpHeaders.AUTHORIZATION)).isNull();
		assertThat(actualRequest.getBody().readUtf8()).contains("grant_type=authorization_code",
				"client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer",
				"client_assertion=");
	}

	@Test
	public void getTokenResponseWhenAuthenticationPrivateKeyJwtThenFormParametersAreSent() throws Exception {
		// @formatter:off
		String accessTokenSuccessResponse = "{\n"
				+ "	  \"access_token\": \"access-token-1234\",\n"
				+ "   \"token_type\": \"bearer\",\n"
				+ "   \"expires_in\": \"3600\"\n"
				+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));

		// @formatter:off
		ClientRegistration clientRegistration = this.clientRegistration
				.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
				.build();
		// @formatter:on

		// Configure Jwt client authentication converter
		JWK jwk = TestJwks.DEFAULT_RSA_JWK;
		Function<ClientRegistration, JWK> jwkResolver = (registration) -> jwk;
		configureJwtClientAuthenticationConverter(jwkResolver);

		this.tokenResponseClient.getTokenResponse(authorizationCodeGrantRequest(clientRegistration)).block();
		RecordedRequest actualRequest = this.server.takeRequest();
		assertThat(actualRequest.getHeader(HttpHeaders.AUTHORIZATION)).isNull();
		assertThat(actualRequest.getBody().readUtf8()).contains("grant_type=authorization_code",
				"client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer",
				"client_assertion=");
	}

	private void configureJwtClientAuthenticationConverter(Function<ClientRegistration, JWK> jwkResolver) {
		NimbusJwtClientAuthenticationParametersConverter<OAuth2AuthorizationCodeGrantRequest> jwtClientAuthenticationConverter = new NimbusJwtClientAuthenticationParametersConverter<>(
				jwkResolver);
		this.tokenResponseClient.addParametersConverter(jwtClientAuthenticationConverter);
	}

	@Test
	public void getTokenResponseWhenErrorResponseThenThrowOAuth2AuthorizationException() {
		String accessTokenErrorResponse = "{\n" + "   \"error\": \"unauthorized_client\"\n" + "}\n";
		this.server.enqueue(
				jsonResponse(accessTokenErrorResponse).setResponseCode(HttpStatus.INTERNAL_SERVER_ERROR.value()));
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
				.isThrownBy(() -> this.tokenResponseClient.getTokenResponse(authorizationCodeGrantRequest()).block())
				.satisfies((ex) -> assertThat(ex.getError().getErrorCode()).isEqualTo("unauthorized_client"))
				.withMessageContaining("unauthorized_client");
	}

	// gh-5594
	@Test
	public void getTokenResponseWhenServerErrorResponseThenThrowOAuth2AuthorizationException() {
		String accessTokenErrorResponse = "{}";
		this.server.enqueue(
				jsonResponse(accessTokenErrorResponse).setResponseCode(HttpStatus.INTERNAL_SERVER_ERROR.value()));
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
				.isThrownBy(() -> this.tokenResponseClient.getTokenResponse(authorizationCodeGrantRequest()).block())
				.withMessageContaining("server_error");
	}

	@Test
	public void getTokenResponseWhenSuccessResponseAndNotBearerTokenTypeThenThrowOAuth2AuthorizationException() {
		// @formatter:off
		String accessTokenSuccessResponse = "{\n"
			+ "\"access_token\": \"access-token-1234\",\n"
			+ "   \"token_type\": \"not-bearer\",\n"
			+ "   \"expires_in\": \"3600\"\n"
			+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
				.isThrownBy(() -> this.tokenResponseClient.getTokenResponse(authorizationCodeGrantRequest()).block())
				.withMessageContaining("invalid_token_response");
	}

	@Test
	public void getTokenResponseWhenSuccessResponseIncludesScopeThenReturnAccessTokenResponseUsingResponseScope() {
		// @formatter:off
		String accessTokenSuccessResponse = "{\n"
			+ "\"access_token\": \"access-token-1234\",\n"
			+ "   \"token_type\": \"bearer\",\n"
			+ "   \"expires_in\": \"3600\",\n"
			+ "   \"scope\": \"openid profile\"\n"
			+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));
		this.clientRegistration.scope("openid", "profile", "email", "address");
		OAuth2AccessTokenResponse accessTokenResponse = this.tokenResponseClient
				.getTokenResponse(authorizationCodeGrantRequest()).block();
		assertThat(accessTokenResponse.getAccessToken().getScopes()).containsExactly("openid", "profile");
	}

	@Test
	public void getTokenResponseWhenSuccessResponseDoesNotIncludeScopeThenReturnAccessTokenResponseWithNoScopes() {
		// @formatter:off
		String accessTokenSuccessResponse = "{\n"
			+ "   \"access_token\": \"access-token-1234\",\n"
			+ "   \"token_type\": \"bearer\",\n"
			+ "   \"expires_in\": \"3600\"\n"
			+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));
		this.clientRegistration.scope("openid", "profile", "email", "address");
		OAuth2AccessTokenResponse accessTokenResponse = this.tokenResponseClient
				.getTokenResponse(authorizationCodeGrantRequest()).block();
		assertThat(accessTokenResponse.getAccessToken().getScopes()).isEmpty();
	}

	private OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest() {
		return authorizationCodeGrantRequest(this.clientRegistration.build());
	}

	private OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest(ClientRegistration registration) {
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.clientId(registration.getClientId()).state("state")
				.authorizationUri(registration.getProviderDetails().getAuthorizationUri())
				.redirectUri(registration.getRedirectUri()).scopes(registration.getScopes()).build();
		OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponse.success("code").state("state")
				.redirectUri(registration.getRedirectUri()).build();
		OAuth2AuthorizationExchange authorizationExchange = new OAuth2AuthorizationExchange(authorizationRequest,
				authorizationResponse);
		return new OAuth2AuthorizationCodeGrantRequest(registration, authorizationExchange);
	}

	private MockResponse jsonResponse(String json) {
		return new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE).setBody(json);
	}

	@Test
	public void setWebClientNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.tokenResponseClient.setWebClient(null));
	}

	@Test
	public void setCustomWebClientThenCustomWebClientIsUsed() {
		WebClient customClient = mock(WebClient.class);
		given(customClient.post()).willReturn(WebClient.builder().build().post());
		this.tokenResponseClient.setWebClient(customClient);
		// @formatter:off
		String accessTokenSuccessResponse = "{\n"
			+ "   \"access_token\": \"access-token-1234\",\n"
			+ "   \"token_type\": \"bearer\",\n"
			+ "   \"expires_in\": \"3600\",\n"
			+ "   \"scope\": \"openid profile\"\n"
			+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));
		this.clientRegistration.scope("openid", "profile", "email", "address");
		OAuth2AccessTokenResponse response = this.tokenResponseClient.getTokenResponse(authorizationCodeGrantRequest())
				.block();
		verify(customClient, atLeastOnce()).post();
	}

	@Test
	public void getTokenResponseWhenOAuth2AuthorizationRequestContainsPkceParametersThenTokenRequestBodyShouldContainCodeVerifier()
			throws Exception {
		// @formatter:off
		String accessTokenSuccessResponse = "{\n"
			+ "   \"access_token\": \"access-token-1234\",\n"
			+ "   \"token_type\": \"bearer\",\n"
			+ "   \"expires_in\": \"3600\"\n"
			+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));
		this.tokenResponseClient.getTokenResponse(pkceAuthorizationCodeGrantRequest()).block();
		String body = this.server.takeRequest().getBody().readUtf8();
		assertThat(body).isEqualTo(
				"grant_type=authorization_code&client_id=client-id&code=code&redirect_uri=%7BbaseUrl%7D%2F%7Baction%7D%2Foauth2%2Fcode%2F%7BregistrationId%7D&code_verifier=code-verifier-1234");
	}

	private OAuth2AuthorizationCodeGrantRequest pkceAuthorizationCodeGrantRequest() {
		ClientRegistration registration = this.clientRegistration.clientAuthenticationMethod(null).clientSecret(null)
				.build();
		Map<String, Object> attributes = new HashMap<>();
		attributes.put(PkceParameterNames.CODE_VERIFIER, "code-verifier-1234");
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE, "code-challenge-1234");
		additionalParameters.put(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
		// @formatter:off
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.clientId(registration.getClientId())
				.state("state")
				.authorizationUri(registration.getProviderDetails().getAuthorizationUri())
				.redirectUri(registration.getRedirectUri())
				.scopes(registration.getScopes())
				.attributes(attributes)
				.additionalParameters(additionalParameters)
				.build();
		OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponse
				.success("code")
				.state("state")
				.redirectUri(registration.getRedirectUri())
				.build();
		// @formatter:on
		OAuth2AuthorizationExchange authorizationExchange = new OAuth2AuthorizationExchange(authorizationRequest,
				authorizationResponse);
		return new OAuth2AuthorizationCodeGrantRequest(registration, authorizationExchange);
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
		OAuth2AuthorizationCodeGrantRequest request = authorizationCodeGrantRequest();
		Converter<OAuth2AuthorizationCodeGrantRequest, HttpHeaders> addedHeadersConverter = mock(Converter.class);
		HttpHeaders headers = new HttpHeaders();
		headers.put("custom-header-name", Collections.singletonList("custom-header-value"));
		given(addedHeadersConverter.convert(request)).willReturn(headers);
		this.tokenResponseClient.addHeadersConverter(addedHeadersConverter);
		// @formatter:off
		String accessTokenSuccessResponse = "{\n"
				+ "   \"access_token\": \"access-token-1234\",\n"
				+ "   \"token_type\": \"bearer\",\n"
				+ "   \"expires_in\": \"3600\",\n"
				+ "   \"scope\": \"openid profile\"\n"
				+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));
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
		OAuth2AuthorizationCodeGrantRequest request = authorizationCodeGrantRequest();
		ClientRegistration clientRegistration = request.getClientRegistration();
		Converter<OAuth2AuthorizationCodeGrantRequest, HttpHeaders> headersConverter = mock(Converter.class);
		HttpHeaders headers = new HttpHeaders();
		headers.setBasicAuth(clientRegistration.getClientId(), clientRegistration.getClientSecret());
		given(headersConverter.convert(request)).willReturn(headers);
		this.tokenResponseClient.setHeadersConverter(headersConverter);
		// @formatter:off
		String accessTokenSuccessResponse = "{\n"
				+ "   \"access_token\": \"access-token-1234\",\n"
				+ "   \"token_type\": \"bearer\",\n"
				+ "   \"expires_in\": \"3600\",\n"
				+ "   \"scope\": \"openid profile\"\n"
				+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));
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
	public void convertWhenParametersConverterAddedThenCalled() throws Exception {
		OAuth2AuthorizationCodeGrantRequest request = authorizationCodeGrantRequest();
		Converter<OAuth2AuthorizationCodeGrantRequest, MultiValueMap<String, String>> addedParametersConverter = mock(
				Converter.class);
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.add("custom-parameter-name", "custom-parameter-value");
		given(addedParametersConverter.convert(request)).willReturn(parameters);
		this.tokenResponseClient.addParametersConverter(addedParametersConverter);
		// @formatter:off
		String accessTokenSuccessResponse = "{\n"
				+ "  \"access_token\":\"MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3\",\n"
				+ "  \"token_type\":\"bearer\",\n"
				+ "  \"expires_in\":3600,\n"
				+ "  \"refresh_token\":\"IwOGYzYTlmM2YxOTQ5MGE3YmNmMDFkNTVk\"\n"
				+ "}";
		// @formatter:on
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));
		this.tokenResponseClient.getTokenResponse(request).block();
		verify(addedParametersConverter).convert(request);
		RecordedRequest actualRequest = this.server.takeRequest();
		assertThat(actualRequest.getBody().readUtf8()).contains("grant_type=authorization_code",
				"custom-parameter-name=custom-parameter-value");
	}

	@Test
	public void convertWhenParametersConverterSetThenCalled() throws Exception {
		OAuth2AuthorizationCodeGrantRequest request = authorizationCodeGrantRequest();
		Converter<OAuth2AuthorizationCodeGrantRequest, MultiValueMap<String, String>> parametersConverter = mock(
				Converter.class);
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.add("custom-parameter-name", "custom-parameter-value");
		given(parametersConverter.convert(request)).willReturn(parameters);
		this.tokenResponseClient.setParametersConverter(parametersConverter);
		// @formatter:off
		String accessTokenSuccessResponse = "{\n"
				+ "  \"access_token\":\"MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3\",\n"
				+ "  \"token_type\":\"bearer\",\n"
				+ "  \"expires_in\":3600,\n"
				+ "  \"refresh_token\":\"IwOGYzYTlmM2YxOTQ5MGE3YmNmMDFkNTVk\"\n"
				+ "}";
		// @formatter:on
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));
		this.tokenResponseClient.getTokenResponse(request).block();
		verify(parametersConverter).convert(request);
		RecordedRequest actualRequest = this.server.takeRequest();
		assertThat(actualRequest.getBody().readUtf8()).contains("custom-parameter-name=custom-parameter-value");
	}

	// gh-10260
	@Test
	public void getTokenResponseWhenSuccessCustomResponseThenReturnAccessTokenResponse() {

		String accessTokenSuccessResponse = "{}";

		WebClientReactiveAuthorizationCodeTokenResponseClient customClient = new WebClientReactiveAuthorizationCodeTokenResponseClient();

		BodyExtractor<Mono<OAuth2AccessTokenResponse>, ReactiveHttpInputMessage> extractor = mock(BodyExtractor.class);
		OAuth2AccessTokenResponse response = TestOAuth2AccessTokenResponses.accessTokenResponse().build();
		given(extractor.extract(any(), any())).willReturn(Mono.just(response));

		customClient.setBodyExtractor(extractor);

		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));
		OAuth2AccessTokenResponse accessTokenResponse = customClient.getTokenResponse(authorizationCodeGrantRequest())
				.block();
		assertThat(accessTokenResponse.getAccessToken()).isNotNull();

	}

}
