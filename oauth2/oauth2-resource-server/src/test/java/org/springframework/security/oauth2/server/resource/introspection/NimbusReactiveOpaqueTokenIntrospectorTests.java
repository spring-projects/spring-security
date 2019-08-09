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

package org.springframework.security.oauth2.server.resource.introspection;

import java.io.IOException;
import java.net.URL;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import net.minidev.json.JSONObject;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.Test;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.AUDIENCE;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.EXPIRES_AT;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.ISSUER;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.NOT_BEFORE;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.SCOPE;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.SUBJECT;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.USERNAME;

/**
 * Tests for {@link NimbusReactiveOpaqueTokenIntrospector}
 */
public class NimbusReactiveOpaqueTokenIntrospectorTests {
	private static final String INTROSPECTION_URL = "https://server.example.com";
	private static final String CLIENT_ID = "client";
	private static final String CLIENT_SECRET = "secret";

	private static final String ACTIVE_RESPONSE = "{\n" +
			"      \"active\": true,\n" +
			"      \"client_id\": \"l238j323ds-23ij4\",\n" +
			"      \"username\": \"jdoe\",\n" +
			"      \"scope\": \"read write dolphin\",\n" +
			"      \"sub\": \"Z5O3upPC88QrAjx00dis\",\n" +
			"      \"aud\": \"https://protected.example.net/resource\",\n" +
			"      \"iss\": \"https://server.example.com/\",\n" +
			"      \"exp\": 1419356238,\n" +
			"      \"iat\": 1419350238,\n" +
			"      \"extension_field\": \"twenty-seven\"\n" +
			"     }";

	private static final String INACTIVE_RESPONSE = "{\n" +
			"      \"active\": false\n" +
			"     }";

	private static final String INVALID_RESPONSE = "{\n" +
			"      \"client_id\": \"l238j323ds-23ij4\",\n" +
			"      \"username\": \"jdoe\",\n" +
			"      \"scope\": \"read write dolphin\",\n" +
			"      \"sub\": \"Z5O3upPC88QrAjx00dis\",\n" +
			"      \"aud\": \"https://protected.example.net/resource\",\n" +
			"      \"iss\": \"https://server.example.com/\",\n" +
			"      \"exp\": 1419356238,\n" +
			"      \"iat\": 1419350238,\n" +
			"      \"extension_field\": \"twenty-seven\"\n" +
			"     }";

	private static final String MALFORMED_ISSUER_RESPONSE = "{\n" +
			"     \"active\" : \"true\",\n" +
			"     \"iss\" : \"badissuer\"\n" +
			"    }";

	@Test
	public void authenticateWhenActiveTokenThenOk() throws Exception {
		try ( MockWebServer server = new MockWebServer() ) {
			server.setDispatcher(requiresAuth(CLIENT_ID, CLIENT_SECRET, ACTIVE_RESPONSE));

			String introspectUri = server.url("/introspect").toString();
			NimbusReactiveOpaqueTokenIntrospector introspectionClient =
					new NimbusReactiveOpaqueTokenIntrospector(introspectUri, CLIENT_ID, CLIENT_SECRET);

			Map<String, Object> attributes = introspectionClient.introspect("token").block();
			assertThat(attributes)
					.isNotNull()
					.containsEntry(OAuth2IntrospectionClaimNames.ACTIVE, true)
					.containsEntry(AUDIENCE, Arrays.asList("https://protected.example.net/resource"))
					.containsEntry(OAuth2IntrospectionClaimNames.CLIENT_ID, "l238j323ds-23ij4")
					.containsEntry(EXPIRES_AT, Instant.ofEpochSecond(1419356238))
					.containsEntry(ISSUER, new URL("https://server.example.com/"))
					.containsEntry(SCOPE, Arrays.asList("read", "write", "dolphin"))
					.containsEntry(SUBJECT, "Z5O3upPC88QrAjx00dis")
					.containsEntry(USERNAME, "jdoe")
					.containsEntry("extension_field", "twenty-seven");
		}
	}

	@Test
	public void authenticateWhenBadClientCredentialsThenAuthenticationException() throws IOException {
		try ( MockWebServer server = new MockWebServer() ) {
			server.setDispatcher(requiresAuth(CLIENT_ID, CLIENT_SECRET, ACTIVE_RESPONSE));

			String introspectUri = server.url("/introspect").toString();
			NimbusReactiveOpaqueTokenIntrospector introspectionClient =
					new NimbusReactiveOpaqueTokenIntrospector(introspectUri, CLIENT_ID, "wrong");

			assertThatCode(() -> introspectionClient.introspect("token").block())
					.isInstanceOf(OAuth2IntrospectionException.class);
		}
	}

	@Test
	public void authenticateWhenInactiveTokenThenInvalidToken() {
		WebClient webClient = mockResponse(INACTIVE_RESPONSE);
		NimbusReactiveOpaqueTokenIntrospector introspectionClient =
				new NimbusReactiveOpaqueTokenIntrospector(INTROSPECTION_URL, webClient);

		assertThatCode(() -> introspectionClient.introspect("token").block())
				.isInstanceOf(OAuth2IntrospectionException.class)
				.extracting("message")
				.containsExactly("Provided token [token] isn't active");
	}

	@Test
	public void authenticateWhenActiveTokenThenParsesValuesInResponse() {
		Map<String, Object> introspectedValues = new HashMap<>();
		introspectedValues.put(OAuth2IntrospectionClaimNames.ACTIVE, true);
		introspectedValues.put(AUDIENCE, Arrays.asList("aud"));
		introspectedValues.put(NOT_BEFORE, 29348723984L);

		WebClient webClient = mockResponse(new JSONObject(introspectedValues).toJSONString());
		NimbusReactiveOpaqueTokenIntrospector introspectionClient =
				new NimbusReactiveOpaqueTokenIntrospector(INTROSPECTION_URL, webClient);

		Map<String, Object> attributes = introspectionClient.introspect("token").block();
		assertThat(attributes)
				.isNotNull()
				.containsEntry(OAuth2IntrospectionClaimNames.ACTIVE, true)
				.containsEntry(AUDIENCE, Arrays.asList("aud"))
				.containsEntry(NOT_BEFORE, Instant.ofEpochSecond(29348723984L))
				.doesNotContainKey(OAuth2IntrospectionClaimNames.CLIENT_ID)
				.doesNotContainKey(SCOPE);
	}

	@Test
	public void authenticateWhenIntrospectionEndpointThrowsExceptionThenInvalidToken() {
		WebClient webClient = mockResponse(new IllegalStateException("server was unresponsive"));
		NimbusReactiveOpaqueTokenIntrospector introspectionClient =
				new NimbusReactiveOpaqueTokenIntrospector(INTROSPECTION_URL, webClient);

		assertThatCode(() -> introspectionClient.introspect("token").block())
				.isInstanceOf(OAuth2IntrospectionException.class)
				.extracting("message")
				.containsExactly("server was unresponsive");
	}

	@Test
	public void authenticateWhenIntrospectionEndpointReturnsMalformedResponseThenInvalidToken() {
		WebClient webClient = mockResponse("malformed");
		NimbusReactiveOpaqueTokenIntrospector introspectionClient =
				new NimbusReactiveOpaqueTokenIntrospector(INTROSPECTION_URL, webClient);

		assertThatCode(() -> introspectionClient.introspect("token").block())
				.isInstanceOf(OAuth2IntrospectionException.class);
	}

	@Test
	public void authenticateWhenIntrospectionTokenReturnsInvalidResponseThenInvalidToken() {
		WebClient webClient = mockResponse(INVALID_RESPONSE);
		NimbusReactiveOpaqueTokenIntrospector introspectionClient =
				new NimbusReactiveOpaqueTokenIntrospector(INTROSPECTION_URL, webClient);

		assertThatCode(() -> introspectionClient.introspect("token").block())
				.isInstanceOf(OAuth2IntrospectionException.class);
	}

	@Test
	public void authenticateWhenIntrospectionTokenReturnsMalformedIssuerResponseThenInvalidToken() {
		WebClient webClient = mockResponse(MALFORMED_ISSUER_RESPONSE);
		NimbusReactiveOpaqueTokenIntrospector introspectionClient =
				new NimbusReactiveOpaqueTokenIntrospector(INTROSPECTION_URL, webClient);

		assertThatCode(() -> introspectionClient.introspect("token").block())
				.isInstanceOf(OAuth2IntrospectionException.class);
	}

	@Test
	public void constructorWhenIntrospectionUriIsEmptyThenIllegalArgumentException() {
		assertThatCode(() -> new NimbusReactiveOpaqueTokenIntrospector("", CLIENT_ID, CLIENT_SECRET))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenClientIdIsEmptyThenIllegalArgumentException() {
		assertThatCode(() -> new NimbusReactiveOpaqueTokenIntrospector(INTROSPECTION_URL, "", CLIENT_SECRET))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenClientSecretIsNullThenIllegalArgumentException() {
		assertThatCode(() -> new NimbusReactiveOpaqueTokenIntrospector(INTROSPECTION_URL, CLIENT_ID, null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenRestOperationsIsNullThenIllegalArgumentException() {
		assertThatCode(() -> new NimbusReactiveOpaqueTokenIntrospector(INTROSPECTION_URL, null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	private WebClient mockResponse(String response) {
		WebClient real = WebClient.builder().build();
		WebClient.RequestBodyUriSpec spec = spy(real.post());
		WebClient webClient = spy(WebClient.class);
		when(webClient.post()).thenReturn(spec);
		ClientResponse clientResponse = mock(ClientResponse.class);
		when(clientResponse.rawStatusCode()).thenReturn(200);
		when(clientResponse.statusCode()).thenReturn(HttpStatus.OK);
		when(clientResponse.bodyToMono(String.class)).thenReturn(Mono.just(response));
		ClientResponse.Headers headers = mock(ClientResponse.Headers.class);
		when(headers.contentType()).thenReturn(Optional.of(MediaType.APPLICATION_JSON_UTF8));
		when(clientResponse.headers()).thenReturn(headers);
		when(spec.exchange()).thenReturn(Mono.just(clientResponse));
		return webClient;
	}

	private WebClient mockResponse(Throwable t) {
		WebClient real = WebClient.builder().build();
		WebClient.RequestBodyUriSpec spec = spy(real.post());
		WebClient webClient = spy(WebClient.class);
		when(webClient.post()).thenReturn(spec);
		when(spec.exchange()).thenThrow(t);
		return webClient;
	}

	private static Dispatcher requiresAuth(String username, String password, String response) {
		return new Dispatcher() {
			@Override
			public MockResponse dispatch(RecordedRequest request) {
				String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
				return Optional.ofNullable(authorization)
						.filter(a -> isAuthorized(authorization, username, password))
						.map(a -> ok(response))
						.orElse(unauthorized());
			}
		};
	}

	private static boolean isAuthorized(String authorization, String username, String password) {
		String[] values = new String(Base64.getDecoder().decode(authorization.substring(6))).split(":");
		return username.equals(values[0]) && password.equals(values[1]);
	}

	private static MockResponse ok(String response) {
		return new MockResponse().setBody(response)
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
	}

	private static MockResponse unauthorized() {
		return new MockResponse().setResponseCode(401);
	}
}
