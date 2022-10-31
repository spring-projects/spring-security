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

import java.net.URLEncoder;
import java.time.Instant;

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
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.TestJwts;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link DefaultJwtBearerTokenResponseClient}.
 *
 * @author Hassene Laaribi
 * @author Joe Grandja
 */
public class DefaultJwtBearerTokenResponseClientTests {

	private DefaultJwtBearerTokenResponseClient tokenResponseClient;

	private ClientRegistration.Builder clientRegistration;

	private Jwt jwtAssertion;

	private MockWebServer server;

	@BeforeEach
	public void setup() throws Exception {
		this.tokenResponseClient = new DefaultJwtBearerTokenResponseClient();
		this.server = new MockWebServer();
		this.server.start();
		String tokenUri = this.server.url("/oauth2/token").toString();
		// @formatter:off
		this.clientRegistration = TestClientRegistrations.clientCredentials()
				.clientId("client-1")
				.clientSecret("secret")
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
	public void setRequestEntityConverterWhenConverterIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.tokenResponseClient.setRequestEntityConverter(null));
	}

	@Test
	public void setRestOperationsWhenRestOperationsIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.tokenResponseClient.setRestOperations(null));
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
				+ "   \"scope\": \"read write\"\n"
				+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));
		Instant expiresAtBefore = Instant.now().plusSeconds(3600);
		ClientRegistration clientRegistration = this.clientRegistration.build();
		JwtBearerGrantRequest jwtBearerGrantRequest = new JwtBearerGrantRequest(clientRegistration, this.jwtAssertion);
		OAuth2AccessTokenResponse accessTokenResponse = this.tokenResponseClient
				.getTokenResponse(jwtBearerGrantRequest);
		Instant expiresAtAfter = Instant.now().plusSeconds(3600);
		RecordedRequest recordedRequest = this.server.takeRequest();
		assertThat(recordedRequest.getMethod()).isEqualTo(HttpMethod.POST.toString());
		assertThat(recordedRequest.getHeader(HttpHeaders.ACCEPT)).isEqualTo(MediaType.APPLICATION_JSON_UTF8_VALUE);
		assertThat(recordedRequest.getHeader(HttpHeaders.CONTENT_TYPE))
				.isEqualTo(MediaType.APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8");
		String formParameters = recordedRequest.getBody().readUtf8();
		assertThat(formParameters)
				.contains("grant_type=" + URLEncoder.encode(AuthorizationGrantType.JWT_BEARER.getValue(), "UTF-8"));
		assertThat(formParameters).contains("scope=read+write");
		assertThat(accessTokenResponse.getAccessToken().getTokenValue()).isEqualTo("access-token-1234");
		assertThat(accessTokenResponse.getAccessToken().getTokenType()).isEqualTo(OAuth2AccessToken.TokenType.BEARER);
		assertThat(accessTokenResponse.getAccessToken().getExpiresAt()).isBetween(expiresAtBefore, expiresAtAfter);
		assertThat(accessTokenResponse.getAccessToken().getScopes()).containsExactlyInAnyOrder("read", "write");
		assertThat(accessTokenResponse.getRefreshToken()).isNull();
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
		JwtBearerGrantRequest jwtBearerGrantRequest = new JwtBearerGrantRequest(this.clientRegistration.build(),
				this.jwtAssertion);
		this.tokenResponseClient.getTokenResponse(jwtBearerGrantRequest);
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
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST).build();
		JwtBearerGrantRequest jwtBearerGrantRequest = new JwtBearerGrantRequest(clientRegistration, this.jwtAssertion);
		this.tokenResponseClient.getTokenResponse(jwtBearerGrantRequest);
		RecordedRequest recordedRequest = this.server.takeRequest();
		assertThat(recordedRequest.getHeader(HttpHeaders.AUTHORIZATION)).isNull();
		String formParameters = recordedRequest.getBody().readUtf8();
		assertThat(formParameters).contains("client_id=client-1");
		assertThat(formParameters).contains("client_secret=secret");
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
		JwtBearerGrantRequest jwtBearerGrantRequest = new JwtBearerGrantRequest(this.clientRegistration.build(),
				this.jwtAssertion);
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
				.isThrownBy(() -> this.tokenResponseClient.getTokenResponse(jwtBearerGrantRequest))
				.withMessageContaining(
						"[invalid_token_response] An error occurred while attempting to retrieve the OAuth 2.0 Access Token Response")
				.havingRootCause().withMessageContaining("tokenType cannot be null");
	}

	@Test
	public void getTokenResponseWhenSuccessResponseIncludesScopeThenAccessTokenHasResponseScope() throws Exception {
		// @formatter:off
		String accessTokenSuccessResponse = "{\n"
				+ "   \"access_token\": \"access-token-1234\",\n"
				+ "   \"token_type\": \"bearer\",\n"
				+ "   \"expires_in\": \"3600\",\n"
				+ "   \"scope\": \"read\"\n"
				+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));
		JwtBearerGrantRequest jwtBearerGrantRequest = new JwtBearerGrantRequest(this.clientRegistration.build(),
				this.jwtAssertion);
		OAuth2AccessTokenResponse accessTokenResponse = this.tokenResponseClient
				.getTokenResponse(jwtBearerGrantRequest);
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
		JwtBearerGrantRequest jwtBearerGrantRequest = new JwtBearerGrantRequest(this.clientRegistration.build(),
				this.jwtAssertion);
		OAuth2AccessTokenResponse accessTokenResponse = this.tokenResponseClient
				.getTokenResponse(jwtBearerGrantRequest);
		assertThat(accessTokenResponse.getAccessToken().getScopes()).isEmpty();
	}

	@Test
	public void getTokenResponseWhenErrorResponseThenThrowOAuth2AuthorizationException() {
		String accessTokenErrorResponse = "{\n" + "   \"error\": \"invalid_grant\"\n" + "}\n";
		this.server.enqueue(jsonResponse(accessTokenErrorResponse).setResponseCode(400));
		JwtBearerGrantRequest jwtBearerGrantRequest = new JwtBearerGrantRequest(this.clientRegistration.build(),
				this.jwtAssertion);
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
				.isThrownBy(() -> this.tokenResponseClient.getTokenResponse(jwtBearerGrantRequest))
				.withMessageContaining("[invalid_grant]");
	}

	@Test
	public void getTokenResponseWhenServerErrorResponseThenThrowOAuth2AuthorizationException() {
		this.server.enqueue(new MockResponse().setResponseCode(500));
		JwtBearerGrantRequest jwtBearerGrantRequest = new JwtBearerGrantRequest(this.clientRegistration.build(),
				this.jwtAssertion);
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
				.isThrownBy(() -> this.tokenResponseClient.getTokenResponse(jwtBearerGrantRequest))
				.withMessageContaining("[invalid_token_response] An error occurred while attempting to "
						+ "retrieve the OAuth 2.0 Access Token Response");
	}

	private MockResponse jsonResponse(String json) {
		return new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE).setBody(json);
	}

}
