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

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOAuth2TokenIntrospectionClient;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2TokenIntrospectionClient;
import org.springframework.web.client.RestOperations;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.AUDIENCE;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.EXPIRES_AT;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.ISSUER;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.NOT_BEFORE;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.SCOPE;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.SUBJECT;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.USERNAME;

/**
 * Tests for {@link NimbusOAuth2TokenIntrospectionClient}
 */
public class NimbusOAuth2TokenIntrospectionClientTests {

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

	private static final ResponseEntity<String> ACTIVE = response(ACTIVE_RESPONSE);
	private static final ResponseEntity<String> INACTIVE = response(INACTIVE_RESPONSE);
	private static final ResponseEntity<String> INVALID = response(INVALID_RESPONSE);
	private static final ResponseEntity<String> MALFORMED_ISSUER = response(MALFORMED_ISSUER_RESPONSE);

	@Test
	public void introspectWhenActiveTokenThenOk() throws Exception {
		try ( MockWebServer server = new MockWebServer() ) {
			server.setDispatcher(requiresAuth(CLIENT_ID, CLIENT_SECRET, ACTIVE_RESPONSE));

			String introspectUri = server.url("/introspect").toString();
			OAuth2TokenIntrospectionClient introspectionClient =
					new NimbusOAuth2TokenIntrospectionClient(introspectUri, CLIENT_ID, CLIENT_SECRET);

			Map<String, Object> attributes = introspectionClient.introspect("token");
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
	public void introspectWhenBadClientCredentialsThenError() throws IOException {
		try ( MockWebServer server = new MockWebServer() ) {
			server.setDispatcher(requiresAuth(CLIENT_ID, CLIENT_SECRET, ACTIVE_RESPONSE));

			String introspectUri = server.url("/introspect").toString();
			OAuth2TokenIntrospectionClient introspectionClient =
					new NimbusOAuth2TokenIntrospectionClient(introspectUri, CLIENT_ID, "wrong");

			assertThatCode(() -> introspectionClient.introspect("token"))
					.isInstanceOf(OAuth2IntrospectionException.class);
		}
	}

	@Test
	public void introspectWhenInactiveTokenThenInvalidToken() {
		RestOperations restOperations = mock(RestOperations.class);
		OAuth2TokenIntrospectionClient introspectionClient = new NimbusOAuth2TokenIntrospectionClient(INTROSPECTION_URL, restOperations);
		when(restOperations.exchange(any(RequestEntity.class), eq(String.class)))
				.thenReturn(INACTIVE);

		assertThatCode(() -> introspectionClient.introspect("token"))
				.isInstanceOf(OAuth2IntrospectionException.class)
				.extracting("message")
				.containsExactly("Provided token [token] isn't active");
	}

	@Test
	public void introspectWhenActiveTokenThenParsesValuesInResponse() {
		Map<String, Object> introspectedValues = new HashMap<>();
		introspectedValues.put(OAuth2IntrospectionClaimNames.ACTIVE, true);
		introspectedValues.put(AUDIENCE, Arrays.asList("aud"));
		introspectedValues.put(NOT_BEFORE, 29348723984L);

		RestOperations restOperations = mock(RestOperations.class);
		OAuth2TokenIntrospectionClient introspectionClient =
				new NimbusOAuth2TokenIntrospectionClient(INTROSPECTION_URL, restOperations);
		when(restOperations.exchange(any(RequestEntity.class), eq(String.class)))
				.thenReturn(response(new JSONObject(introspectedValues).toJSONString()));

		Map<String, Object> attributes = introspectionClient.introspect("token");
		assertThat(attributes)
				.isNotNull()
				.containsEntry(OAuth2IntrospectionClaimNames.ACTIVE, true)
				.containsEntry(AUDIENCE, Arrays.asList("aud"))
				.containsEntry(NOT_BEFORE, Instant.ofEpochSecond(29348723984L))
				.doesNotContainKey(OAuth2IntrospectionClaimNames.CLIENT_ID)
				.doesNotContainKey(SCOPE);
	}

	@Test
	public void introspectWhenIntrospectionEndpointThrowsExceptionThenInvalidToken() {
		RestOperations restOperations = mock(RestOperations.class);
		OAuth2TokenIntrospectionClient introspectionClient =
				new NimbusOAuth2TokenIntrospectionClient(INTROSPECTION_URL, restOperations);
		when(restOperations.exchange(any(RequestEntity.class), eq(String.class)))
				.thenThrow(new IllegalStateException("server was unresponsive"));

		assertThatCode(() -> introspectionClient.introspect("token"))
				.isInstanceOf(OAuth2IntrospectionException.class)
				.extracting("message")
				.containsExactly("server was unresponsive");
	}


	@Test
	public void introspectWhenIntrospectionEndpointReturnsMalformedResponseThenInvalidToken() {
		RestOperations restOperations = mock(RestOperations.class);
		OAuth2TokenIntrospectionClient introspectionClient =
				new NimbusOAuth2TokenIntrospectionClient(INTROSPECTION_URL, restOperations);
		when(restOperations.exchange(any(RequestEntity.class), eq(String.class)))
				.thenReturn(response("malformed"));

		assertThatCode(() -> introspectionClient.introspect("token"))
				.isInstanceOf(OAuth2IntrospectionException.class);
	}

	@Test
	public void introspectWhenIntrospectionTokenReturnsInvalidResponseThenInvalidToken() {
		RestOperations restOperations = mock(RestOperations.class);
		OAuth2TokenIntrospectionClient introspectionClient =
				new NimbusOAuth2TokenIntrospectionClient(INTROSPECTION_URL, restOperations);
		when(restOperations.exchange(any(RequestEntity.class), eq(String.class)))
				.thenReturn(INVALID);

		assertThatCode(() -> introspectionClient.introspect("token"))
				.isInstanceOf(OAuth2IntrospectionException.class);
	}

	@Test
	public void introspectWhenIntrospectionTokenReturnsMalformedIssuerResponseThenInvalidToken() {
		RestOperations restOperations = mock(RestOperations.class);
		OAuth2TokenIntrospectionClient introspectionClient =
				new NimbusOAuth2TokenIntrospectionClient(INTROSPECTION_URL, restOperations);
		when(restOperations.exchange(any(RequestEntity.class), eq(String.class)))
				.thenReturn(MALFORMED_ISSUER);

		assertThatCode(() -> introspectionClient.introspect("token"))
				.isInstanceOf(OAuth2IntrospectionException.class);
	}

	@Test
	public void constructorWhenIntrospectionUriIsNullThenIllegalArgumentException() {
		assertThatCode(() -> new NimbusOAuth2TokenIntrospectionClient(null, CLIENT_ID, CLIENT_SECRET))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenClientIdIsNullThenIllegalArgumentException() {
		assertThatCode(() -> new NimbusOAuth2TokenIntrospectionClient(INTROSPECTION_URL, null, CLIENT_SECRET))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenClientSecretIsNullThenIllegalArgumentException() {
		assertThatCode(() -> new NimbusOAuth2TokenIntrospectionClient(INTROSPECTION_URL, CLIENT_ID, null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenRestOperationsIsNullThenIllegalArgumentException() {
		assertThatCode(() -> new NimbusOAuth2TokenIntrospectionClient(INTROSPECTION_URL, null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	private static ResponseEntity<String> response(String content) {
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		return new ResponseEntity<>(content, headers, HttpStatus.OK);
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
