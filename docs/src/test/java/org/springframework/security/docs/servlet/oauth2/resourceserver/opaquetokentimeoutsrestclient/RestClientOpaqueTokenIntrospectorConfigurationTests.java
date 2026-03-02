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

package org.springframework.security.docs.servlet.oauth2.resourceserver.opaquetokentimeoutsrestclient;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.RestClientOpaqueTokenIntrospector;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link RestClientOpaqueTokenIntrospectorConfiguration} sample snippets.
 */
class RestClientOpaqueTokenIntrospectorConfigurationTests {

	private static final String CLIENT_ID = "client";

	private static final String CLIENT_SECRET = "secret";

	private static final String ACTIVE_RESPONSE = """
			{
			  "active": true,
			  "sub": "Z5O3upPC88QrAjx00dis",
			  "scope": "read write",
			  "exp": 1419356238,
			  "iat": 1419350238
			}
			""";

	@Test
	void introspectorWhenBuilderThenIntrospectsSuccessfully() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			server.setDispatcher(requiresAuth(CLIENT_ID, CLIENT_SECRET, ACTIVE_RESPONSE));
			String introspectionUri = server.url("/introspect").toString();
			OpaqueTokenIntrospector introspector = RestClientOpaqueTokenIntrospector
				.withIntrospectionUri(introspectionUri)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.build();
			OAuth2AuthenticatedPrincipal principal = introspector.introspect("token");
			assertThat(principal.getAttributes()).isNotNull()
				.containsEntry(OAuth2TokenIntrospectionClaimNames.ACTIVE, true)
				.containsEntry(OAuth2TokenIntrospectionClaimNames.SUB, "Z5O3upPC88QrAjx00dis")
				.containsEntry(OAuth2TokenIntrospectionClaimNames.EXP, Instant.ofEpochSecond(1419356238));
			assertThat((List<String>) principal.getAttribute(OAuth2TokenIntrospectionClaimNames.SCOPE))
				.isEqualTo(Arrays.asList("read", "write"));
		}
	}

	@Test
	void introspectorWithTimeoutsWhenCustomRestClientThenIntrospectsSuccessfully() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			server.setDispatcher(requiresAuth(CLIENT_ID, CLIENT_SECRET, ACTIVE_RESPONSE));
			String introspectionUri = server.url("/introspect").toString();
			SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
			requestFactory.setConnectTimeout(Duration.ofSeconds(60));
			requestFactory.setReadTimeout(Duration.ofSeconds(60));
			RestClient restClient = RestClient.builder()
				.requestFactory(requestFactory)
				.defaultHeaders((headers) -> headers.setBasicAuth(CLIENT_ID, CLIENT_SECRET))
				.build();
			OpaqueTokenIntrospector introspector = new RestClientOpaqueTokenIntrospector(introspectionUri, restClient);
			OAuth2AuthenticatedPrincipal principal = introspector.introspect("token");
			assertThat(principal.getAttributes()).isNotNull()
				.containsEntry(OAuth2TokenIntrospectionClaimNames.ACTIVE, true)
				.containsEntry(OAuth2TokenIntrospectionClaimNames.SUB, "Z5O3upPC88QrAjx00dis");
		}
	}

	private static Dispatcher requiresAuth(String username, String password, String response) {
		return new Dispatcher() {
			@Override
			public MockResponse dispatch(RecordedRequest request) {
				String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
				return Optional.ofNullable(authorization)
					.filter((a) -> isAuthorized(authorization, username, password))
					.map((a) -> new MockResponse().setBody(response)
						.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE))
					.orElse(new MockResponse().setResponseCode(401));
			}
		};
	}

	private static boolean isAuthorized(String authorization, String username, String password) {
		String decoded = new String(Base64.getDecoder().decode(authorization.substring(6)));
		String[] values = decoded.split(":", 2);
		return values.length == 2 && username.equals(values[0]) && password.equals(values[1]);
	}

}
