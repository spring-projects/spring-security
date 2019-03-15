/*
 * Copyright 2002-2018 the original author or authors.
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

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * @author Rob Winch
 * @since 5.1
 */
public class WebClientReactiveAuthorizationCodeTokenResponseClientTests {
	private ClientRegistration.Builder clientRegistration;

	private WebClientReactiveAuthorizationCodeTokenResponseClient tokenResponseClient = new WebClientReactiveAuthorizationCodeTokenResponseClient();

	private MockWebServer server;

	@Before
	public void setup() throws Exception {
		this.server = new MockWebServer();
		this.server.start();

		String tokenUri = this.server.url("/oauth2/token").toString();

		this.clientRegistration = TestClientRegistrations.clientRegistration()
				.tokenUri(tokenUri);
	}

	@After
	public void cleanup() throws Exception {
		this.server.shutdown();
	}

	@Test
	public void getTokenResponseWhenSuccessResponseThenReturnAccessTokenResponse() throws Exception {
		String accessTokenSuccessResponse = "{\n" +
				"	\"access_token\": \"access-token-1234\",\n" +
				"   \"token_type\": \"bearer\",\n" +
				"   \"expires_in\": \"3600\",\n" +
				"   \"scope\": \"openid profile\",\n" +
				"	\"refresh_token\": \"refresh-token-1234\",\n" +
				"   \"custom_parameter_1\": \"custom-value-1\",\n" +
				"   \"custom_parameter_2\": \"custom-value-2\"\n" +
				"}\n";
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));


		Instant expiresAtBefore = Instant.now().plusSeconds(3600);

		OAuth2AccessTokenResponse accessTokenResponse = this.tokenResponseClient.getTokenResponse(authorizationCodeGrantRequest()).block();

		Instant expiresAtAfter = Instant.now().plusSeconds(3600);

		assertThat(accessTokenResponse.getAccessToken().getTokenValue()).isEqualTo("access-token-1234");
		assertThat(accessTokenResponse.getAccessToken().getTokenType()).isEqualTo(
				OAuth2AccessToken.TokenType.BEARER);
		assertThat(accessTokenResponse.getAccessToken().getExpiresAt()).isBetween(expiresAtBefore, expiresAtAfter);
		assertThat(accessTokenResponse.getAccessToken().getScopes()).containsExactly("openid", "profile");
		assertThat(accessTokenResponse.getRefreshToken().getTokenValue()).isEqualTo("refresh-token-1234");
		assertThat(accessTokenResponse.getAdditionalParameters().size()).isEqualTo(2);
		assertThat(accessTokenResponse.getAdditionalParameters()).containsEntry("custom_parameter_1", "custom-value-1");
		assertThat(accessTokenResponse.getAdditionalParameters()).containsEntry("custom_parameter_2", "custom-value-2");
	}

//	@Test
//	public void getTokenResponseWhenRedirectUriMalformedThenThrowIllegalArgumentException() throws Exception {
//		this.exception.expect(IllegalArgumentException.class);
//
//		String redirectUri = "http:\\example.com";
//		when(this.clientRegistration.getRedirectUriTemplate()).thenReturn(redirectUri);
//
//		this.tokenResponseClient.getTokenResponse(
//				new OAuth2AuthorizationCodeGrantRequest(this.clientRegistration, this.authorizationExchange));
//	}
//
//	@Test
//	public void getTokenResponseWhenTokenUriMalformedThenThrowIllegalArgumentException() throws Exception {
//		this.exception.expect(IllegalArgumentException.class);
//
//		String tokenUri = "http:\\provider.com\\oauth2\\token";
//		when(this.providerDetails.getTokenUri()).thenReturn(tokenUri);
//
//		this.tokenResponseClient.getTokenResponse(
//				new OAuth2AuthorizationCodeGrantRequest(this.clientRegistration, this.authorizationExchange));
//	}
//
//	@Test
//	public void getTokenResponseWhenSuccessResponseInvalidThenThrowOAuth2AuthorizationException() throws Exception {
//		this.exception.expect(OAuth2AuthorizationException.class);
//		this.exception.expectMessage(containsString("invalid_token_response"));
//
//		MockWebServer server = new MockWebServer();
//
//		String accessTokenSuccessResponse = "{\n" +
//				"	\"access_token\": \"access-token-1234\",\n" +
//				"   \"token_type\": \"bearer\",\n" +
//				"   \"expires_in\": \"3600\",\n" +
//				"   \"scope\": \"openid profile\",\n" +
//				"   \"custom_parameter_1\": \"custom-value-1\",\n" +
//				"   \"custom_parameter_2\": \"custom-value-2\"\n";
//		//			"}\n";		// Make the JSON invalid/malformed
//
//		server.enqueue(new MockResponse()
//				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
//				.setBody(accessTokenSuccessResponse));
//		server.start();
//
//		String tokenUri = server.url("/oauth2/token").toString();
//		when(this.providerDetails.getTokenUri()).thenReturn(tokenUri);
//
//		try {
//			this.tokenResponseClient.getTokenResponse(
//					new OAuth2AuthorizationCodeGrantRequest(this.clientRegistration, this.authorizationExchange));
//		} finally {
//			server.shutdown();
//		}
//	}
//
//	@Test
//	public void getTokenResponseWhenTokenUriInvalidThenThrowAuthenticationServiceException() throws Exception {
//		this.exception.expect(AuthenticationServiceException.class);
//
//		String tokenUri = "http://invalid-provider.com/oauth2/token";
//		when(this.providerDetails.getTokenUri()).thenReturn(tokenUri);
//
//		this.tokenResponseClient.getTokenResponse(
//				new OAuth2AuthorizationCodeGrantRequest(this.clientRegistration, this.authorizationExchange));
//	}
//
	@Test
	public void getTokenResponseWhenErrorResponseThenThrowOAuth2AuthorizationException() throws Exception {
		String accessTokenErrorResponse = "{\n" +
				"   \"error\": \"unauthorized_client\"\n" +
				"}\n";

		this.server.enqueue(jsonResponse(accessTokenErrorResponse).setResponseCode(HttpStatus.INTERNAL_SERVER_ERROR.value()));

		assertThatThrownBy(() -> this.tokenResponseClient.getTokenResponse(authorizationCodeGrantRequest()).block())
			.isInstanceOf(OAuth2AuthorizationException.class)
			.hasMessageContaining("unauthorized_client");
	}

	// gh-5594
	@Test
	public void getTokenResponseWhenServerErrorResponseThenThrowOAuth2AuthorizationException() throws Exception {
		String accessTokenErrorResponse = "{}";
		this.server.enqueue(jsonResponse(accessTokenErrorResponse).setResponseCode(HttpStatus.INTERNAL_SERVER_ERROR.value()));

		assertThatThrownBy(() -> this.tokenResponseClient.getTokenResponse(authorizationCodeGrantRequest()).block())
				.isInstanceOf(OAuth2AuthorizationException.class)
				.hasMessageContaining("server_error");
	}

	@Test
	public void getTokenResponseWhenSuccessResponseAndNotBearerTokenTypeThenThrowOAuth2AuthorizationException() throws Exception {
		String accessTokenSuccessResponse = "{\n" +
				"	\"access_token\": \"access-token-1234\",\n" +
				"   \"token_type\": \"not-bearer\",\n" +
				"   \"expires_in\": \"3600\"\n" +
				"}\n";

		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));

		assertThatThrownBy(() -> this.tokenResponseClient.getTokenResponse(authorizationCodeGrantRequest()).block())
				.isInstanceOf(OAuth2AuthorizationException.class)
				.hasMessageContaining("invalid_token_response");
	}

	@Test
	public void getTokenResponseWhenSuccessResponseIncludesScopeThenReturnAccessTokenResponseUsingResponseScope() throws Exception {
		String accessTokenSuccessResponse = "{\n" +
				"	\"access_token\": \"access-token-1234\",\n" +
				"   \"token_type\": \"bearer\",\n" +
				"   \"expires_in\": \"3600\",\n" +
				"   \"scope\": \"openid profile\"\n" +
				"}\n";
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));

		this.clientRegistration.scope("openid", "profile", "email", "address");

		OAuth2AccessTokenResponse accessTokenResponse = this.tokenResponseClient.getTokenResponse(authorizationCodeGrantRequest()).block();

		assertThat(accessTokenResponse.getAccessToken().getScopes()).containsExactly("openid", "profile");
	}

	@Test
	public void getTokenResponseWhenSuccessResponseDoesNotIncludeScopeThenReturnAccessTokenResponseUsingRequestedScope() throws Exception {
		String accessTokenSuccessResponse = "{\n" +
				"	\"access_token\": \"access-token-1234\",\n" +
				"   \"token_type\": \"bearer\",\n" +
				"   \"expires_in\": \"3600\"\n" +
				"}\n";
		this.server.enqueue(jsonResponse(accessTokenSuccessResponse));


		this.clientRegistration.scope("openid", "profile", "email", "address");

		OAuth2AccessTokenResponse accessTokenResponse = this.tokenResponseClient.getTokenResponse(authorizationCodeGrantRequest()).block();

		assertThat(accessTokenResponse.getAccessToken().getScopes()).containsExactly("openid", "profile", "email", "address");
	}

	private OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest() {
		ClientRegistration registration = this.clientRegistration.build();
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest
				.authorizationCode()
				.clientId(registration.getClientId())
				.state("state")
				.authorizationUri(registration.getProviderDetails().getAuthorizationUri())
				.redirectUri(registration.getRedirectUriTemplate())
				.scopes(registration.getScopes())
				.build();
		OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponse
				.success("code")
				.state("state")
				.redirectUri(registration.getRedirectUriTemplate())
				.build();
		OAuth2AuthorizationExchange authorizationExchange = new OAuth2AuthorizationExchange(authorizationRequest,
				authorizationResponse);
		return new OAuth2AuthorizationCodeGrantRequest(registration, authorizationExchange);
	}

	private MockResponse jsonResponse(String json) {
		return new MockResponse()
			.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
			.setBody(json);
	}
}
