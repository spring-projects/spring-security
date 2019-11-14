/*
 * Copyright 2002-2019 the original author or authors.
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

import java.time.Instant;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link DefaultPasswordTokenResponseClient}.
 *
 * @author Joe Grandja
 */
public class DefaultPasswordTokenResponseClientTests {
	private DefaultPasswordTokenResponseClient tokenResponseClient = new DefaultPasswordTokenResponseClient();
	private ClientRegistration.Builder clientRegistrationBuilder;
	private String username = "user1";
	private String password = "password";
	private MockWebServer server;

	@Before
	public void setup() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
		String tokenUri = this.server.url("/oauth2/token").toString();
		this.clientRegistrationBuilder = TestClientRegistrations.clientRegistration()
				.authorizationGrantType(AuthorizationGrantType.PASSWORD)
				.scope("read", "write")
				.tokenUri(tokenUri);
	}

	@After
	public void cleanup() throws Exception {
		this.server.shutdown();
	}

	@Test
	public void setRequestEntityConverterWhenConverterIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.tokenResponseClient.setRequestEntityConverter(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void setRestOperationsWhenRestOperationsIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.tokenResponseClient.setRestOperations(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void getTokenResponseWhenRequestIsNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.tokenResponseClient.getTokenResponse(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void getTokenResponseWhenSuccessResponseThenReturnAccessTokenResponse() throws Exception {
		String accessTokenSuccessResponse = "{\n" +
				"	\"access_token\": \"access-token-1234\",\n" +
				"   \"token_type\": \"bearer\",\n" +
				"   \"expires_in\": \"3600\"\n" +
				"}\n";
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));

		Instant expiresAtBefore = Instant.now().plusSeconds(3600);

		ClientRegistration clientRegistration = this.clientRegistrationBuilder.build();
		OAuth2PasswordGrantRequest passwordGrantRequest = new OAuth2PasswordGrantRequest(
				clientRegistration, this.username, this.password);

		OAuth2AccessTokenResponse accessTokenResponse = this.tokenResponseClient.getTokenResponse(passwordGrantRequest);

		Instant expiresAtAfter = Instant.now().plusSeconds(3600);

		RecordedRequest recordedRequest = this.server.takeRequest();
		assertThat(recordedRequest.getMethod()).isEqualTo(HttpMethod.POST.toString());
		assertThat(recordedRequest.getHeader(HttpHeaders.ACCEPT)).isEqualTo(MediaType.APPLICATION_JSON_UTF8_VALUE);
		assertThat(recordedRequest.getHeader(HttpHeaders.CONTENT_TYPE)).isEqualTo(MediaType.APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8");

		String formParameters = recordedRequest.getBody().readUtf8();
		assertThat(formParameters).contains("grant_type=password");
		assertThat(formParameters).contains("username=user1");
		assertThat(formParameters).contains("password=password");
		assertThat(formParameters).contains("scope=read+write");

		assertThat(accessTokenResponse.getAccessToken().getTokenValue()).isEqualTo("access-token-1234");
		assertThat(accessTokenResponse.getAccessToken().getTokenType()).isEqualTo(OAuth2AccessToken.TokenType.BEARER);
		assertThat(accessTokenResponse.getAccessToken().getExpiresAt()).isBetween(expiresAtBefore, expiresAtAfter);
		assertThat(accessTokenResponse.getAccessToken().getScopes()).containsExactly(clientRegistration.getScopes().toArray(new String[0]));
		assertThat(accessTokenResponse.getRefreshToken()).isNull();
	}

	@Test
	public void getTokenResponseWhenClientAuthenticationPostThenFormParametersAreSent() throws Exception {
		String accessTokenSuccessResponse = "{\n" +
				"	\"access_token\": \"access-token-1234\",\n" +
				"   \"token_type\": \"bearer\",\n" +
				"   \"expires_in\": \"3600\"\n" +
				"}\n";
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));

		ClientRegistration clientRegistration = this.clientRegistrationBuilder
				.clientAuthenticationMethod(ClientAuthenticationMethod.POST)
				.build();
		OAuth2PasswordGrantRequest passwordGrantRequest = new OAuth2PasswordGrantRequest(
				clientRegistration, this.username, this.password);

		this.tokenResponseClient.getTokenResponse(passwordGrantRequest);

		RecordedRequest recordedRequest = this.server.takeRequest();
		assertThat(recordedRequest.getHeader(HttpHeaders.AUTHORIZATION)).isNull();

		String formParameters = recordedRequest.getBody().readUtf8();
		assertThat(formParameters).contains("client_id=client-id");
		assertThat(formParameters).contains("client_secret=client-secret");
	}

	@Test
	public void getTokenResponseWhenSuccessResponseAndNotBearerTokenTypeThenThrowOAuth2AuthorizationException() {
		String accessTokenSuccessResponse = "{\n" +
				"	\"access_token\": \"access-token-1234\",\n" +
				"   \"token_type\": \"not-bearer\",\n" +
				"   \"expires_in\": \"3600\"\n" +
				"}\n";
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));

		OAuth2PasswordGrantRequest passwordGrantRequest = new OAuth2PasswordGrantRequest(
				this.clientRegistrationBuilder.build(), this.username, this.password);

		assertThatThrownBy(() -> this.tokenResponseClient.getTokenResponse(passwordGrantRequest))
				.isInstanceOf(OAuth2AuthorizationException.class)
				.hasMessageContaining("[invalid_token_response] An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response")
				.hasMessageContaining("tokenType cannot be null");
	}

	@Test
	public void getTokenResponseWhenSuccessResponseIncludesScopeThenAccessTokenHasResponseScope() throws Exception {
		String accessTokenSuccessResponse = "{\n" +
				"	\"access_token\": \"access-token-1234\",\n" +
				"   \"token_type\": \"bearer\",\n" +
				"   \"expires_in\": \"3600\",\n" +
				"   \"scope\": \"read\"\n" +
				"}\n";
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));

		OAuth2PasswordGrantRequest passwordGrantRequest = new OAuth2PasswordGrantRequest(
				this.clientRegistrationBuilder.build(), this.username, this.password);

		OAuth2AccessTokenResponse accessTokenResponse = this.tokenResponseClient.getTokenResponse(passwordGrantRequest);

		RecordedRequest recordedRequest = this.server.takeRequest();
		String formParameters = recordedRequest.getBody().readUtf8();
		assertThat(formParameters).contains("scope=read");

		assertThat(accessTokenResponse.getAccessToken().getScopes()).containsExactly("read");
	}

	@Test
	public void getTokenResponseWhenErrorResponseThenThrowOAuth2AuthorizationException() {
		String accessTokenErrorResponse = "{\n" +
				"   \"error\": \"unauthorized_client\"\n" +
				"}\n";
		this.server.enqueue(jsonResponse(accessTokenErrorResponse).setResponseCode(400));

		OAuth2PasswordGrantRequest passwordGrantRequest = new OAuth2PasswordGrantRequest(
				this.clientRegistrationBuilder.build(), this.username, this.password);

		assertThatThrownBy(() -> this.tokenResponseClient.getTokenResponse(passwordGrantRequest))
				.isInstanceOf(OAuth2AuthorizationException.class)
				.hasMessageContaining("[unauthorized_client]");
	}

	@Test
	public void getTokenResponseWhenServerErrorResponseThenThrowOAuth2AuthorizationException() {
		this.server.enqueue(new MockResponse().setResponseCode(500));

		OAuth2PasswordGrantRequest passwordGrantRequest = new OAuth2PasswordGrantRequest(
				this.clientRegistrationBuilder.build(), this.username, this.password);

		assertThatThrownBy(() -> this.tokenResponseClient.getTokenResponse(passwordGrantRequest))
				.isInstanceOf(OAuth2AuthorizationException.class)
				.hasMessageContaining("[invalid_token_response] An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response");
	}

	private MockResponse jsonResponse(String json) {
		return new MockResponse()
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setBody(json);
	}
}
