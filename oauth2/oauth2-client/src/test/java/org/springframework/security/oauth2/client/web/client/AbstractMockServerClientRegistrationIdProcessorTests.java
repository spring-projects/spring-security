/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.client.web.client;

import java.io.IOException;

import okhttp3.HttpUrl;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.ClientRegistrationId;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.invoker.HttpExchangeAdapter;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Base class for integration testing {@link ClientRegistrationIdProcessor} with
 * {@link MockWebServer}.
 *
 * @author Rob Winch
 * @since 7.0
 */
abstract class AbstractMockServerClientRegistrationIdProcessorTests {

	static final String REGISTRATION_ID = "okta";

	private final MockWebServer server = new MockWebServer();

	private OAuth2AccessToken accessToken;

	protected String baseUrl;

	protected OAuth2AuthorizedClient authorizedClient;

	@BeforeEach
	void setup() throws IOException {
		this.server.start();
		HttpUrl url = this.server.url("/range/");
		this.baseUrl = url.toString();
		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration()
			.registrationId(REGISTRATION_ID)
			.build();
		this.accessToken = TestOAuth2AccessTokens.scopes("read", "write");
		this.authorizedClient = new OAuth2AuthorizedClient(clientRegistration, "user", this.accessToken);
	}

	@AfterEach
	void cleanup() throws IOException {
		if (this.server != null) {
			this.server.shutdown();
		}
	}

	void testWithAdapter(HttpExchangeAdapter adapter) throws InterruptedException {
		ClientRegistrationIdProcessor processor = ClientRegistrationIdProcessor.DEFAULT_INSTANCE;
		HttpServiceProxyFactory factory = HttpServiceProxyFactory.builder()
			.exchangeAdapter(adapter)
			.httpRequestValuesProcessor(processor)
			.build();
		MessageClient messages = factory.createClient(MessageClient.class);

		this.server.enqueue(new MockResponse().setBody("Hello OAuth2!").setResponseCode(200));
		assertThat(messages.getMessage()).isEqualTo("Hello OAuth2!");

		String authorizationHeader = this.server.takeRequest().getHeader(HttpHeaders.AUTHORIZATION);
		assertOAuthTokenValue(authorizationHeader, this.accessToken);

	}

	private static void assertOAuthTokenValue(String value, OAuth2AccessToken accessToken) {
		String tokenType = accessToken.getTokenType().getValue();
		String tokenValue = accessToken.getTokenValue();
		assertThat(value).isEqualTo("%s %s".formatted(tokenType, tokenValue));
	}

	interface MessageClient {

		@GetExchange("/message")
		@ClientRegistrationId(REGISTRATION_ID)
		String getMessage();

	}

}
