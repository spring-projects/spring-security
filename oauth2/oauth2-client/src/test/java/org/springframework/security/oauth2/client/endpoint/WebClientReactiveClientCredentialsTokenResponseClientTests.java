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

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.validateMockitoUsage;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 */
public class WebClientReactiveClientCredentialsTokenResponseClientTests {

	private MockWebServer server;

	private WebClientReactiveClientCredentialsTokenResponseClient client = new WebClientReactiveClientCredentialsTokenResponseClient();

	private ClientRegistration.Builder clientRegistration;

	@Before
	public void setup() throws Exception {
		this.server = new MockWebServer();
		this.server.start();

		this.clientRegistration = TestClientRegistrations.clientCredentials()
				.tokenUri(this.server.url("/oauth2/token").uri().toASCIIString());
	}

	@After
	public void cleanup() throws Exception {
		validateMockitoUsage();
		this.server.shutdown();
	}

	@Test
	public void getTokenResponseWhenHeaderThenSuccess() throws Exception {
		enqueueJson("{\n" + "  \"access_token\":\"MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3\",\n"
				+ "  \"token_type\":\"bearer\",\n" + "  \"expires_in\":3600,\n"
				+ "  \"refresh_token\":\"IwOGYzYTlmM2YxOTQ5MGE3YmNmMDFkNTVk\",\n" + "  \"scope\":\"create\"\n" + "}");
		OAuth2ClientCredentialsGrantRequest request = new OAuth2ClientCredentialsGrantRequest(
				this.clientRegistration.build());

		OAuth2AccessTokenResponse response = this.client.getTokenResponse(request).block();
		RecordedRequest actualRequest = this.server.takeRequest();
		String body = actualRequest.getUtf8Body();

		assertThat(response.getAccessToken()).isNotNull();
		assertThat(actualRequest.getHeader(HttpHeaders.AUTHORIZATION))
				.isEqualTo("Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=");
		assertThat(body).isEqualTo("grant_type=client_credentials&scope=read%3Auser");
	}

	@Test
	public void getTokenResponseWhenPostThenSuccess() throws Exception {
		ClientRegistration registration = this.clientRegistration
				.clientAuthenticationMethod(ClientAuthenticationMethod.POST).build();
		enqueueJson("{\n" + "  \"access_token\":\"MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3\",\n"
				+ "  \"token_type\":\"bearer\",\n" + "  \"expires_in\":3600,\n"
				+ "  \"refresh_token\":\"IwOGYzYTlmM2YxOTQ5MGE3YmNmMDFkNTVk\",\n" + "  \"scope\":\"create\"\n" + "}");

		OAuth2ClientCredentialsGrantRequest request = new OAuth2ClientCredentialsGrantRequest(registration);

		OAuth2AccessTokenResponse response = this.client.getTokenResponse(request).block();
		RecordedRequest actualRequest = this.server.takeRequest();
		String body = actualRequest.getUtf8Body();

		assertThat(response.getAccessToken()).isNotNull();
		assertThat(actualRequest.getHeader(HttpHeaders.AUTHORIZATION)).isNull();
		assertThat(body).isEqualTo(
				"grant_type=client_credentials&client_id=client-id&client_secret=client-secret&scope=read%3Auser");
	}

	@Test
	public void getTokenResponseWhenNoScopeThenClientRegistrationScopesDefaulted() {
		ClientRegistration registration = this.clientRegistration.build();
		enqueueJson("{\n" + "  \"access_token\":\"MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3\",\n"
				+ "  \"token_type\":\"bearer\",\n" + "  \"expires_in\":3600,\n"
				+ "  \"refresh_token\":\"IwOGYzYTlmM2YxOTQ5MGE3YmNmMDFkNTVk\"\n" + "}");
		OAuth2ClientCredentialsGrantRequest request = new OAuth2ClientCredentialsGrantRequest(registration);

		OAuth2AccessTokenResponse response = this.client.getTokenResponse(request).block();

		assertThat(response.getAccessToken().getScopes()).isEqualTo(registration.getScopes());
	}

	@Test(expected = IllegalArgumentException.class)
	public void setWebClientNullThenIllegalArgumentException() {
		this.client.setWebClient(null);
	}

	@Test
	public void setWebClientCustomThenCustomClientIsUsed() {
		WebClient customClient = mock(WebClient.class);
		given(customClient.post()).willReturn(WebClient.builder().build().post());

		this.client.setWebClient(customClient);
		ClientRegistration registration = this.clientRegistration.build();
		enqueueJson("{\n" + "  \"access_token\":\"MTQ0NjJkZmQ5OTM2NDE1ZTZjNGZmZjI3\",\n"
				+ "  \"token_type\":\"bearer\",\n" + "  \"expires_in\":3600,\n"
				+ "  \"refresh_token\":\"IwOGYzYTlmM2YxOTQ5MGE3YmNmMDFkNTVk\"\n" + "}");
		OAuth2ClientCredentialsGrantRequest request = new OAuth2ClientCredentialsGrantRequest(registration);

		OAuth2AccessTokenResponse response = this.client.getTokenResponse(request).block();

		verify(customClient, atLeastOnce()).post();
	}

	@Test
	public void getTokenResponseWhenInvalidResponse() throws WebClientResponseException {
		ClientRegistration registration = this.clientRegistration.build();
		enqueueUnexpectedResponse();

		OAuth2ClientCredentialsGrantRequest request = new OAuth2ClientCredentialsGrantRequest(registration);

		assertThatThrownBy(() -> this.client.getTokenResponse(request).block())
				.isInstanceOfSatisfying(OAuth2AuthorizationException.class,
						(e) -> assertThat(e.getError().getErrorCode()).isEqualTo("invalid_token_response"))
				.hasMessageContaining("[invalid_token_response]")
				.hasMessageContaining("Empty OAuth 2.0 Access Token Response");

	}

	private void enqueueUnexpectedResponse() {
		MockResponse response = new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setResponseCode(301);
		this.server.enqueue(response);
	}

	private void enqueueJson(String body) {
		MockResponse response = new MockResponse().setBody(body).setHeader(HttpHeaders.CONTENT_TYPE,
				MediaType.APPLICATION_JSON_VALUE);
		this.server.enqueue(response);
	}

}
