/*
 * Copyright 2002-2020 the original author or authors.
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
import java.util.Collections;

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
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.TestOAuth2RefreshTokens;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link DefaultRefreshTokenTokenResponseClient}.
 *
 * @author Joe Grandja
 */
public class DefaultRefreshTokenTokenResponseClientTests {

	private DefaultRefreshTokenTokenResponseClient tokenResponseClient = new DefaultRefreshTokenTokenResponseClient();

	private ClientRegistration.Builder clientRegistrationBuilder;

	private OAuth2AccessToken accessToken;

	private OAuth2RefreshToken refreshToken;

	private MockWebServer server;

	@Before
	public void setup() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
		String tokenUri = this.server.url("/oauth2/token").toString();
		this.clientRegistrationBuilder = TestClientRegistrations.clientRegistration().tokenUri(tokenUri);
		this.accessToken = TestOAuth2AccessTokens.scopes("read", "write");
		this.refreshToken = TestOAuth2RefreshTokens.refreshToken();
	}

	@After
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
			+ "   \"expires_in\": \"3600\"\n"
			+ "}\n";
		// @formatter:on
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));
		Instant expiresAtBefore = Instant.now().plusSeconds(3600);
		OAuth2RefreshTokenGrantRequest refreshTokenGrantRequest = new OAuth2RefreshTokenGrantRequest(
				this.clientRegistrationBuilder.build(), this.accessToken, this.refreshToken);
		OAuth2AccessTokenResponse accessTokenResponse = this.tokenResponseClient
				.getTokenResponse(refreshTokenGrantRequest);
		Instant expiresAtAfter = Instant.now().plusSeconds(3600);
		RecordedRequest recordedRequest = this.server.takeRequest();
		assertThat(recordedRequest.getMethod()).isEqualTo(HttpMethod.POST.toString());
		assertThat(recordedRequest.getHeader(HttpHeaders.ACCEPT)).isEqualTo(MediaType.APPLICATION_JSON_UTF8_VALUE);
		assertThat(recordedRequest.getHeader(HttpHeaders.CONTENT_TYPE))
				.isEqualTo(MediaType.APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8");
		assertThat(recordedRequest.getHeader(HttpHeaders.AUTHORIZATION)).startsWith("Basic ");
		String formParameters = recordedRequest.getBody().readUtf8();
		assertThat(formParameters).contains("grant_type=refresh_token");
		assertThat(formParameters).contains("refresh_token=refresh-token");
		assertThat(accessTokenResponse.getAccessToken().getTokenValue()).isEqualTo("access-token-1234");
		assertThat(accessTokenResponse.getAccessToken().getTokenType()).isEqualTo(OAuth2AccessToken.TokenType.BEARER);
		assertThat(accessTokenResponse.getAccessToken().getExpiresAt()).isBetween(expiresAtBefore, expiresAtAfter);
		assertThat(accessTokenResponse.getAccessToken().getScopes())
				.containsExactly(this.accessToken.getScopes().toArray(new String[0]));
		assertThat(accessTokenResponse.getRefreshToken().getTokenValue()).isEqualTo(this.refreshToken.getTokenValue());
	}

	@Test
	public void getTokenResponseWhenClientAuthenticationPostThenFormParametersAreSent() throws Exception {
		String accessTokenSuccessResponse = "{\n" + "	\"access_token\": \"access-token-1234\",\n"
				+ "   \"token_type\": \"bearer\",\n" + "   \"expires_in\": \"3600\"\n" + "}\n";
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));
		ClientRegistration clientRegistration = this.clientRegistrationBuilder
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST).build();
		OAuth2RefreshTokenGrantRequest refreshTokenGrantRequest = new OAuth2RefreshTokenGrantRequest(clientRegistration,
				this.accessToken, this.refreshToken);
		this.tokenResponseClient.getTokenResponse(refreshTokenGrantRequest);
		RecordedRequest recordedRequest = this.server.takeRequest();
		assertThat(recordedRequest.getHeader(HttpHeaders.AUTHORIZATION)).isNull();
		String formParameters = recordedRequest.getBody().readUtf8();
		assertThat(formParameters).contains("client_id=client-id");
		assertThat(formParameters).contains("client_secret=client-secret");
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
		OAuth2RefreshTokenGrantRequest refreshTokenGrantRequest = new OAuth2RefreshTokenGrantRequest(
				this.clientRegistrationBuilder.build(), this.accessToken, this.refreshToken);
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
				.isThrownBy(() -> this.tokenResponseClient.getTokenResponse(refreshTokenGrantRequest))
				.withMessageContaining("[invalid_token_response] An error occurred while attempting to "
						+ "retrieve the OAuth 2.0 Access Token Response")
				.withMessageContaining("tokenType cannot be null");
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
		OAuth2RefreshTokenGrantRequest refreshTokenGrantRequest = new OAuth2RefreshTokenGrantRequest(
				this.clientRegistrationBuilder.build(), this.accessToken, this.refreshToken,
				Collections.singleton("read"));
		OAuth2AccessTokenResponse accessTokenResponse = this.tokenResponseClient
				.getTokenResponse(refreshTokenGrantRequest);
		RecordedRequest recordedRequest = this.server.takeRequest();
		String formParameters = recordedRequest.getBody().readUtf8();
		assertThat(formParameters).contains("scope=read");
		assertThat(accessTokenResponse.getAccessToken().getScopes()).containsExactly("read");
	}

	@Test
	public void getTokenResponseWhenErrorResponseThenThrowOAuth2AuthorizationException() {
		String accessTokenErrorResponse = "{\n" + "   \"error\": \"unauthorized_client\"\n" + "}\n";
		this.server.enqueue(jsonResponse(accessTokenErrorResponse).setResponseCode(400));
		OAuth2RefreshTokenGrantRequest refreshTokenGrantRequest = new OAuth2RefreshTokenGrantRequest(
				this.clientRegistrationBuilder.build(), this.accessToken, this.refreshToken);
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
				.isThrownBy(() -> this.tokenResponseClient.getTokenResponse(refreshTokenGrantRequest))
				.withMessageContaining("[unauthorized_client]");
	}

	@Test
	public void getTokenResponseWhenServerErrorResponseThenThrowOAuth2AuthorizationException() {
		this.server.enqueue(new MockResponse().setResponseCode(500));
		OAuth2RefreshTokenGrantRequest refreshTokenGrantRequest = new OAuth2RefreshTokenGrantRequest(
				this.clientRegistrationBuilder.build(), this.accessToken, this.refreshToken);
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
				.isThrownBy(() -> this.tokenResponseClient.getTokenResponse(refreshTokenGrantRequest))
				.withMessageContaining("[invalid_token_response] An error occurred while attempting to "
						+ "retrieve the OAuth 2.0 Access Token Response");
	}

	private MockResponse jsonResponse(String json) {
		return new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE).setBody(json);
	}

}
