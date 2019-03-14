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
package org.springframework.security.oauth2.server.resource.authentication;

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
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.web.client.RestOperations;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames.AUDIENCE;
import static org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames.EXPIRES_AT;
import static org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames.ISSUER;
import static org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames.NOT_BEFORE;
import static org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames.SCOPE;
import static org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames.SUBJECT;
import static org.springframework.security.oauth2.server.resource.authentication.OAuth2IntrospectionClaimNames.USERNAME;

/**
 * Tests for {@link OAuth2IntrospectionAuthenticationProvider}
 *
 * @author Josh Cummings
 * @since 5.2
 */
public class OAuth2IntrospectionAuthenticationProviderTests {
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
	public void authenticateWhenActiveTokenThenOk() throws Exception {
		try ( MockWebServer server = new MockWebServer() ) {
			server.setDispatcher(requiresAuth(CLIENT_ID, CLIENT_SECRET, ACTIVE_RESPONSE));

			String introspectUri = server.url("/introspect").toString();
			OAuth2IntrospectionAuthenticationProvider provider =
					new OAuth2IntrospectionAuthenticationProvider(introspectUri, CLIENT_ID, CLIENT_SECRET);

			Authentication result =
					provider.authenticate(new BearerTokenAuthenticationToken("token"));

			assertThat(result.getPrincipal()).isInstanceOf(Map.class);

			Map<String, Object> attributes = (Map<String, Object>) result.getPrincipal();
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

			assertThat(result.getAuthorities()).extracting("authority")
					.containsExactly("SCOPE_read", "SCOPE_write", "SCOPE_dolphin");
		}
	}

	@Test
	public void authenticateWhenBadClientCredentialsThenAuthenticationException() throws IOException {
		try ( MockWebServer server = new MockWebServer() ) {
			server.setDispatcher(requiresAuth(CLIENT_ID, CLIENT_SECRET, ACTIVE_RESPONSE));

			String introspectUri = server.url("/introspect").toString();
			OAuth2IntrospectionAuthenticationProvider provider =
					new OAuth2IntrospectionAuthenticationProvider(introspectUri, CLIENT_ID, "wrong");

			assertThatCode(() -> provider.authenticate(new BearerTokenAuthenticationToken("token")))
					.isInstanceOf(OAuth2AuthenticationException.class);
		}
	}

	@Test
	public void authenticateWhenInactiveTokenThenInvalidToken() {
		RestOperations restOperations = mock(RestOperations.class);
		OAuth2IntrospectionAuthenticationProvider provider =
				new OAuth2IntrospectionAuthenticationProvider(INTROSPECTION_URL, restOperations);
		when(restOperations.exchange(any(RequestEntity.class), eq(String.class)))
				.thenReturn(INACTIVE);

		assertThatCode(() -> provider.authenticate(new BearerTokenAuthenticationToken("token")))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting("error.errorCode")
				.containsExactly("invalid_token");
	}

	@Test
	public void authenticateWhenActiveTokenThenParsesValuesInResponse() {
		Map<String, Object> introspectedValues = new HashMap<>();
		introspectedValues.put(OAuth2IntrospectionClaimNames.ACTIVE, true);
		introspectedValues.put(AUDIENCE, Arrays.asList("aud"));
		introspectedValues.put(NOT_BEFORE, 29348723984L);

		RestOperations restOperations = mock(RestOperations.class);
		OAuth2IntrospectionAuthenticationProvider provider =
				new OAuth2IntrospectionAuthenticationProvider(INTROSPECTION_URL, restOperations);
		when(restOperations.exchange(any(RequestEntity.class), eq(String.class)))
				.thenReturn(response(new JSONObject(introspectedValues).toJSONString()));

		Authentication result =
				provider.authenticate(new BearerTokenAuthenticationToken("token"));

		assertThat(result.getPrincipal()).isInstanceOf(Map.class);

		Map<String, Object> attributes = (Map<String, Object>) result.getPrincipal();
		assertThat(attributes)
				.isNotNull()
				.containsEntry(OAuth2IntrospectionClaimNames.ACTIVE, true)
				.containsEntry(AUDIENCE, Arrays.asList("aud"))
				.containsEntry(NOT_BEFORE, Instant.ofEpochSecond(29348723984L))
				.doesNotContainKey(OAuth2IntrospectionClaimNames.CLIENT_ID)
				.doesNotContainKey(SCOPE);

		assertThat(result.getAuthorities()).isEmpty();
	}

	@Test
	public void authenticateWhenIntrospectionEndpointThrowsExceptionThenInvalidToken() {
		RestOperations restOperations = mock(RestOperations.class);
		OAuth2IntrospectionAuthenticationProvider provider =
				new OAuth2IntrospectionAuthenticationProvider(INTROSPECTION_URL, restOperations);
		when(restOperations.exchange(any(RequestEntity.class), eq(String.class)))
				.thenThrow(new IllegalStateException("server was unresponsive"));

		assertThatCode(() -> provider.authenticate(new BearerTokenAuthenticationToken("token")))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting("error.errorCode")
				.containsExactly("invalid_token");
	}


	@Test
	public void authenticateWhenIntrospectionEndpointReturnsMalformedResponseThenInvalidToken() {
		RestOperations restOperations = mock(RestOperations.class);
		OAuth2IntrospectionAuthenticationProvider provider =
				new OAuth2IntrospectionAuthenticationProvider(INTROSPECTION_URL, restOperations);
		when(restOperations.exchange(any(RequestEntity.class), eq(String.class)))
				.thenReturn(response("malformed"));

		assertThatCode(() -> provider.authenticate(new BearerTokenAuthenticationToken("token")))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting("error.errorCode")
				.containsExactly("invalid_token");
	}

	@Test
	public void authenticateWhenIntrospectionTokenReturnsInvalidResponseThenInvalidToken() {
		RestOperations restOperations = mock(RestOperations.class);
		OAuth2IntrospectionAuthenticationProvider provider =
				new OAuth2IntrospectionAuthenticationProvider(INTROSPECTION_URL, restOperations);
		when(restOperations.exchange(any(RequestEntity.class), eq(String.class)))
				.thenReturn(INVALID);

		assertThatCode(() -> provider.authenticate(new BearerTokenAuthenticationToken("token")))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting("error.errorCode")
				.containsExactly("invalid_token");
	}

	@Test
	public void authenticateWhenIntrospectionTokenReturnsMalformedIssuerResponseThenInvalidToken() {
		RestOperations restOperations = mock(RestOperations.class);
		OAuth2IntrospectionAuthenticationProvider provider =
				new OAuth2IntrospectionAuthenticationProvider(INTROSPECTION_URL, restOperations);
		when(restOperations.exchange(any(RequestEntity.class), eq(String.class)))
				.thenReturn(MALFORMED_ISSUER);

		assertThatCode(() -> provider.authenticate(new BearerTokenAuthenticationToken("token")))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting("error.errorCode")
				.containsExactly("invalid_token");
	}

	@Test
	public void constructorWhenIntrospectionUriIsNullThenIllegalArgumentException() {
		assertThatCode(() -> new OAuth2IntrospectionAuthenticationProvider(null, CLIENT_ID, CLIENT_SECRET))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenClientIdIsNullThenIllegalArgumentException() {
		assertThatCode(() -> new OAuth2IntrospectionAuthenticationProvider(INTROSPECTION_URL, null, CLIENT_SECRET))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenClientSecretIsNullThenIllegalArgumentException() {
		assertThatCode(() -> new OAuth2IntrospectionAuthenticationProvider(INTROSPECTION_URL, CLIENT_ID, null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenRestOperationsIsNullThenIllegalArgumentException() {
		assertThatCode(() -> new OAuth2IntrospectionAuthenticationProvider(INTROSPECTION_URL, null))
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
