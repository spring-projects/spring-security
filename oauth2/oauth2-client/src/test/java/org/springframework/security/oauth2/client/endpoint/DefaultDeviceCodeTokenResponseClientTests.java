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
import java.util.function.Function;

import com.nimbusds.jose.jwk.JWK;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.jose.TestJwks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link DefaultDeviceCodeTokenResponseClient}.
 *
 * @author Max Batischev
 */
public class DefaultDeviceCodeTokenResponseClientTests {

	private DefaultDeviceCodeTokenResponseClient tokenResponseClient;

	private ClientRegistration.Builder clientRegistration;

	private MockWebServer server;

	private static final String DEVICE_CODE = "device_code";

	@BeforeEach
	public void setup() throws Exception {
		this.tokenResponseClient = new DefaultDeviceCodeTokenResponseClient();
		this.server = new MockWebServer();
		this.server.start();
		String tokenUri = this.server.url("/oauth2/token").toString();
		// @formatter:off
		this.clientRegistration = TestClientRegistrations.deviceCode()
				.clientId("client-1")
				.clientSecret("secret")
				.tokenUri(tokenUri)
				.scope("read", "write");
		// @formatter:on
	}

	@AfterEach
	public void cleanup() throws Exception {
		this.server.shutdown();
	}

	@Test
	public void setRequestEntityConverterWhenConverterIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.tokenResponseClient.setRequestEntityConverter(null));
		// @formatter:on
	}

	@Test
	public void setRestOperationsWhenRestOperationsIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.tokenResponseClient.setRestOperations(null));
		// @formatter:on
	}

	@Test
	public void getTokenResponseWhenRequestIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.tokenResponseClient.getTokenResponse(null));
	}

	@Test
	public void getTokenResponseWhenSuccessResponseThenReturnAccessTokenResponse() throws Exception {
		// @formatter:off
		String accessTokenSuccessResponse = "{\n"
				+ "   \"access_token\": \"access-token-1234\",\n"
				+ "   \"token_type\": \"bearer\",\n"
				+ "   \"expires_in\": \"3600\",\n"
				+ "   \"scope\": \"read write\",\n"
				+ "   \"custom_parameter_1\": \"custom-value-1\",\n"
				+ "   \"custom_parameter_2\": \"custom-value-2\"\n"
				+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));
		Instant expiresAtBefore = Instant.now().plusSeconds(3600);

		OAuth2AccessTokenResponse accessTokenResponse = this.tokenResponseClient
			.getTokenResponse(deviceCodeGrantRequest());

		Instant expiresAtAfter = Instant.now().plusSeconds(3600);
		RecordedRequest recordedRequest = this.server.takeRequest();
		assertThat(recordedRequest.getMethod()).isEqualTo(HttpMethod.POST.toString());
		assertThat(recordedRequest.getHeader(HttpHeaders.ACCEPT)).isEqualTo(MediaType.APPLICATION_JSON_UTF8_VALUE);
		assertThat(recordedRequest.getHeader(HttpHeaders.CONTENT_TYPE))
			.isEqualTo(MediaType.APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8");
		String formParameters = recordedRequest.getBody().readUtf8();
		assertThat(formParameters).contains("grant_type="
				+ URLEncoder.encode(AuthorizationGrantType.DEVICE_CODE.getValue(), StandardCharsets.UTF_8));
		assertThat(formParameters).contains("scope=read+write");
		assertThat(accessTokenResponse.getAccessToken().getTokenValue()).isEqualTo("access-token-1234");
		assertThat(accessTokenResponse.getAccessToken().getTokenType()).isEqualTo(OAuth2AccessToken.TokenType.BEARER);
		assertThat(accessTokenResponse.getAccessToken().getExpiresAt()).isBetween(expiresAtBefore, expiresAtAfter);
		assertThat(accessTokenResponse.getAccessToken().getScopes()).containsExactly("read", "write");
		assertThat(accessTokenResponse.getRefreshToken()).isNull();
		assertThat(accessTokenResponse.getAdditionalParameters()).hasSize(2);
		assertThat(accessTokenResponse.getAdditionalParameters()).containsEntry("custom_parameter_1", "custom-value-1");
		assertThat(accessTokenResponse.getAdditionalParameters()).containsEntry("custom_parameter_2", "custom-value-2");
	}

	@Test
	public void getTokenResponseWhenAuthenticationClientSecretBasicThenAuthorizationHeaderIsSent() throws Exception {
		// @formatter:off
		String accessTokenSuccessResponse = "{\n"
				+ "   \"access_token\": \"access-token-1234\",\n"
				+ "   \"token_type\": \"bearer\",\n"
				+ "   \"expires_in\": \"3600\"\n"
				+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));

		this.tokenResponseClient.getTokenResponse(deviceCodeGrantRequest());

		RecordedRequest recordedRequest = this.server.takeRequest();
		assertThat(recordedRequest.getHeader(HttpHeaders.AUTHORIZATION)).startsWith("Basic ");
	}

	@Test
	public void getTokenResponseWhenAuthenticationClientSecretPostThenFormParametersAreSent() throws Exception {
		// @formatter:off
		String accessTokenSuccessResponse = "{\n"
				+ "	\"access_token\": \"access-token-1234\",\n"
				+ "   \"token_type\": \"bearer\",\n"
				+ "   \"expires_in\": \"3600\"\n"
				+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));
		ClientRegistration clientRegistration = this.clientRegistration
			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
			.build();

		this.tokenResponseClient.getTokenResponse(deviceCodeGrantRequest());

		RecordedRequest recordedRequest = this.server.takeRequest();
		assertThat(recordedRequest.getHeader(HttpHeaders.AUTHORIZATION)).isNull();
		String formParameters = recordedRequest.getBody().readUtf8();
		assertThat(formParameters).contains("client_id=client-1");
		assertThat(formParameters).contains("client_secret=secret");
	}

	@Test
	public void getTokenResponseWhenAuthenticationPrivateKeyJwtThenFormParametersAreSent() throws Exception {
		// @formatter:off
		String accessTokenSuccessResponse = "{\n"
				+ "	\"access_token\": \"access-token-1234\",\n"
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

		this.tokenResponseClient.getTokenResponse(deviceCodeGrantRequest());

		RecordedRequest recordedRequest = this.server.takeRequest();
		assertThat(recordedRequest.getHeader(HttpHeaders.AUTHORIZATION)).isNull();
		String formParameters = recordedRequest.getBody().readUtf8();
		assertThat(formParameters)
			.contains("client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer");
		assertThat(formParameters).contains("client_assertion=");
	}

	private void configureJwtClientAuthenticationConverter(Function<ClientRegistration, JWK> jwkResolver) {
		NimbusJwtClientAuthenticationParametersConverter<OAuth2DeviceCodeGrantRequest> jwtClientAuthenticationConverter = new NimbusJwtClientAuthenticationParametersConverter<>(
				jwkResolver);
		OAuth2DeviceCodeGrantRequestEntityConverter converter = new OAuth2DeviceCodeGrantRequestEntityConverter();
		converter.addParametersConverter(jwtClientAuthenticationConverter);

		this.tokenResponseClient.setRequestEntityConverter(converter);
	}

	@Test
	public void getTokenResponseWhenSuccessResponseAndNotBearerTokenTypeThenThrowOAuth2AuthorizationException() {
		// @formatter:off
		String accessTokenSuccessResponse = "{\n"
				+ "   \"access_token\": \"access-token-1234\",\n"
				+ "   \"token_type\": \"not-bearer\",\n"
				+ "   \"expires_in\": \"3600\"\n"
				+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));

		assertThatExceptionOfType(OAuth2AuthorizationException.class)
			.isThrownBy(() -> this.tokenResponseClient.getTokenResponse(deviceCodeGrantRequest()))
			.withMessageContaining(
					"[invalid_token_response] An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response")
			.havingRootCause()
			.withMessageContaining("tokenType cannot be null");
	}

	@Test
	public void getTokenResponseWhenSuccessResponseAndMissingTokenTypeParameterThenThrowOAuth2AuthorizationException() {
		String accessTokenSuccessResponse = "{\n" + "	\"access_token\": \"access-token-1234\"\n" + "}\n";
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));

		assertThatExceptionOfType(OAuth2AuthorizationException.class)
			.isThrownBy(() -> this.tokenResponseClient.getTokenResponse(deviceCodeGrantRequest()))
			.withMessageContaining(
					"[invalid_token_response] An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response")
			.havingRootCause()
			.withMessageContaining("tokenType cannot be null");
	}

	@Test
	public void getTokenResponseWhenSuccessResponseIncludesScopeThenAccessTokenHasResponseScope() {
		// @formatter:off
		String accessTokenSuccessResponse = "{\n"
				+ "   \"access_token\": \"access-token-1234\",\n"
				+ "   \"token_type\": \"bearer\",\n"
				+ "   \"expires_in\": \"3600\",\n"
				+ "   \"scope\": \"read\"\n"
				+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));

		OAuth2AccessTokenResponse accessTokenResponse = this.tokenResponseClient
			.getTokenResponse(deviceCodeGrantRequest());
		assertThat(accessTokenResponse.getAccessToken().getScopes()).containsExactly("read");
	}

	@Test
	public void getTokenResponseWhenSuccessResponseDoesNotIncludeScopeThenAccessTokenHasNoScope() {
		// @formatter:off
		String accessTokenSuccessResponse = "{\n"
				+ "   \"access_token\": \"access-token-1234\",\n"
				+ "   \"token_type\": \"bearer\",\n"
				+ "   \"expires_in\": \"3600\"\n"
				+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));

		OAuth2AccessTokenResponse accessTokenResponse = this.tokenResponseClient
			.getTokenResponse(deviceCodeGrantRequest());
		assertThat(accessTokenResponse.getAccessToken().getScopes()).isEmpty();
	}

	@Test
	public void getTokenResponseWhenTokenUriInvalidThenThrowOAuth2AuthorizationException() {
		String invalidTokenUri = "https://invalid-provider.com/oauth2/token";
		ClientRegistration clientRegistration = this.clientRegistration.tokenUri(invalidTokenUri).build();

		assertThatExceptionOfType(OAuth2AuthorizationException.class)
			.isThrownBy(() -> this.tokenResponseClient.getTokenResponse(deviceCodeGrantRequest(clientRegistration)))
			.withMessageContaining(
					"[invalid_token_response] An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response");
	}

	@Test
	public void getTokenResponseWhenMalformedResponseThenThrowOAuth2AuthorizationException() {
		// @formatter:off
		String accessTokenSuccessResponse = "{\n"
				+ "   \"access_token\": \"access-token-1234\",\n"
				+ "   \"token_type\": \"bearer\",\n"
				+ "   \"expires_in\": \"3600\",\n"
				+ "   \"scope\": \"read write\",\n"
				+ "   \"custom_parameter_1\": \"custom-value-1\",\n"
				+ "   \"custom_parameter_2\": \"custom-value-2\"\n";
		// "}\n"; // Make the JSON invalid/malformed
		// @formatter:on
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));

		assertThatExceptionOfType(OAuth2AuthorizationException.class)
			.isThrownBy(() -> this.tokenResponseClient.getTokenResponse(deviceCodeGrantRequest()))
			.withMessageContaining(
					"[invalid_token_response] An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response");
	}

	@Test
	public void getTokenResponseWhenErrorResponseThenThrowOAuth2AuthorizationException() {
		// @formatter:off
		String accessTokenErrorResponse = "{\n"
				+ "   \"error\": \"unauthorized_client\"\n"
				+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(accessTokenErrorResponse).setResponseCode(400));

		assertThatExceptionOfType(OAuth2AuthorizationException.class)
			.isThrownBy(() -> this.tokenResponseClient.getTokenResponse(deviceCodeGrantRequest()))
			.withMessageContaining("[unauthorized_client]");
	}

	@Test
	public void getTokenResponseWhenServerErrorResponseThenThrowOAuth2AuthorizationException() {
		this.server.enqueue(new MockResponse().setResponseCode(500));

		assertThatExceptionOfType(OAuth2AuthorizationException.class)
			.isThrownBy(() -> this.tokenResponseClient.getTokenResponse(deviceCodeGrantRequest()))
			.withMessageContaining(
					"[invalid_token_response] An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response");
	}

	private MockResponse jsonResponse(String json) {
		return new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE).setBody(json);
	}

	private OAuth2DeviceCodeGrantRequest deviceCodeGrantRequest() {
		return new OAuth2DeviceCodeGrantRequest(this.clientRegistration.build(), DEVICE_CODE);
	}

	private OAuth2DeviceCodeGrantRequest deviceCodeGrantRequest(ClientRegistration clientRegistration) {
		return new OAuth2DeviceCodeGrantRequest(clientRegistration, DEVICE_CODE);
	}

}
