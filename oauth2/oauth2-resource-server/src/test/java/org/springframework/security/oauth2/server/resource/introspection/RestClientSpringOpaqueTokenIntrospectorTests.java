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

package org.springframework.security.oauth2.server.resource.introspection;

import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;

import com.nimbusds.jose.util.JSONObjectUtils;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link RestClientSpringOpaqueTokenIntrospector}
 *
 * @author Andrey Litvitski
 */
public class RestClientSpringOpaqueTokenIntrospectorTests {

	private static final String INTROSPECTION_URL = "https://server.example.com";

	private static final String CLIENT_ID = "client";

	private static final String CLIENT_SECRET = "secret";

	// @formatter:off
	private static final String ACTIVE_RESPONSE = "{\n"
			+ "      \"active\": true,\n"
			+ "      \"client_id\": \"l238j323ds-23ij4\",\n"
			+ "      \"username\": \"jdoe\",\n"
			+ "      \"scope\": \"read write dolphin\",\n"
			+ "      \"sub\": \"Z5O3upPC88QrAjx00dis\",\n"
			+ "      \"aud\": \"https://protected.example.net/resource\",\n"
			+ "      \"iss\": \"https://server.example.com/\",\n"
			+ "      \"exp\": 1419356238,\n"
			+ "      \"iat\": 1419350238,\n"
			+ "      \"extension_field\": \"twenty-seven\"\n"
			+ "     }";
	// @formatter:on

	// @formatter:off
	private static final String INACTIVE_RESPONSE = "{\n"
			+ "      \"active\": false\n"
			+ "     }";
	// @formatter:on

	// @formatter:off
	private static final String INVALID_RESPONSE = "{\n"
			+ "      \"client_id\": \"l238j323ds-23ij4\",\n"
			+ "      \"username\": \"jdoe\",\n"
			+ "      \"scope\": \"read write dolphin\",\n"
			+ "      \"sub\": \"Z5O3upPC88QrAjx00dis\",\n"
			+ "      \"aud\": \"https://protected.example.net/resource\",\n"
			+ "      \"iss\": \"https://server.example.com/\",\n"
			+ "      \"exp\": 1419356238,\n"
			+ "      \"iat\": 1419350238,\n"
			+ "      \"extension_field\": \"twenty-seven\"\n"
			+ "     }";
	// @formatter:on

	// @formatter:off
	private static final String MALFORMED_SCOPE_RESPONSE = "{\n"
			+ "      \"active\": true,\n"
			+ "      \"client_id\": \"l238j323ds-23ij4\",\n"
			+ "      \"username\": \"jdoe\",\n"
			+ "      \"scope\": [ \"read\", \"write\", \"dolphin\" ],\n"
			+ "      \"sub\": \"Z5O3upPC88QrAjx00dis\",\n"
			+ "      \"aud\": \"https://protected.example.net/resource\",\n"
			+ "      \"iss\": \"https://server.example.com/\",\n"
			+ "      \"exp\": 1419356238,\n"
			+ "      \"iat\": 1419350238,\n"
			+ "      \"extension_field\": \"twenty-seven\"\n"
			+ "     }";
	// @formatter:on

	@Test
	public void introspectWhenActiveTokenThenOk() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			server.setDispatcher(requiresAuth(CLIENT_ID, CLIENT_SECRET, ACTIVE_RESPONSE));
			String introspectUri = server.url("/introspect").toString();
			OpaqueTokenIntrospector introspectionClient = RestClientSpringOpaqueTokenIntrospector
				.withIntrospectionUri(introspectUri)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.build();
			OAuth2AuthenticatedPrincipal authority = introspectionClient.introspect("token");
			// @formatter:off
			assertThat(authority.getAttributes())
					.isNotNull()
					.containsEntry(OAuth2TokenIntrospectionClaimNames.ACTIVE, true)
					.containsEntry(OAuth2TokenIntrospectionClaimNames.AUD,
							Arrays.asList("https://protected.example.net/resource"))
					.containsEntry(OAuth2TokenIntrospectionClaimNames.CLIENT_ID, "l238j323ds-23ij4")
					.containsEntry(OAuth2TokenIntrospectionClaimNames.EXP, Instant.ofEpochSecond(1419356238))
					.containsEntry(OAuth2TokenIntrospectionClaimNames.ISS, "https://server.example.com/")
					.containsEntry(OAuth2TokenIntrospectionClaimNames.SCOPE, Arrays.asList("read", "write", "dolphin"))
					.containsEntry(OAuth2TokenIntrospectionClaimNames.SUB, "Z5O3upPC88QrAjx00dis")
					.containsEntry(OAuth2TokenIntrospectionClaimNames.USERNAME, "jdoe")
					.containsEntry("extension_field", "twenty-seven");
			// @formatter:on
		}
	}

	@Test
	public void introspectWhenBadClientCredentialsThenError() throws IOException {
		try (MockWebServer server = new MockWebServer()) {
			server.setDispatcher(requiresAuth(CLIENT_ID, CLIENT_SECRET, ACTIVE_RESPONSE));
			String introspectUri = server.url("/introspect").toString();
			OpaqueTokenIntrospector introspectionClient = RestClientSpringOpaqueTokenIntrospector
				.withIntrospectionUri(introspectUri)
				.clientId(CLIENT_ID)
				.clientSecret("wrong")
				.build();
			assertThatExceptionOfType(OAuth2IntrospectionException.class)
				.isThrownBy(() -> introspectionClient.introspect("token"));
		}
	}

	@Test
	public void introspectWhenInactiveTokenThenInvalidToken() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			server.setDispatcher(requiresAuth(CLIENT_ID, CLIENT_SECRET, INACTIVE_RESPONSE));
			String introspectUri = server.url("/introspect").toString();
			OpaqueTokenIntrospector introspectionClient = RestClientSpringOpaqueTokenIntrospector
				.withIntrospectionUri(introspectUri)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.build();

			assertThatExceptionOfType(OAuth2IntrospectionException.class)
				.isThrownBy(() -> introspectionClient.introspect("token"))
				.withMessage("Provided token isn't active");
		}
	}

	@Test
	public void introspectWhenActiveTokenThenParsesValuesInResponse() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			String response = """
					{
					  "active": true,
					  "aud": ["aud"],
					  "nbf": 29348723984
					}
					""";
			server.setDispatcher(requiresAuth(CLIENT_ID, CLIENT_SECRET, response));
			String introspectUri = server.url("/introspect").toString();
			OpaqueTokenIntrospector introspectionClient = RestClientSpringOpaqueTokenIntrospector
				.withIntrospectionUri(introspectUri)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.build();
			OAuth2AuthenticatedPrincipal authority = introspectionClient.introspect("token");
			assertThat(authority.getAttributes()).isNotNull()
				.containsEntry(OAuth2TokenIntrospectionClaimNames.ACTIVE, true)
				.containsEntry(OAuth2TokenIntrospectionClaimNames.AUD, Arrays.asList("aud"))
				.containsEntry(OAuth2TokenIntrospectionClaimNames.NBF, Instant.ofEpochSecond(29348723984L))
				.doesNotContainKey(OAuth2TokenIntrospectionClaimNames.CLIENT_ID)
				.doesNotContainKey(OAuth2TokenIntrospectionClaimNames.SCOPE);
		}
	}

	@Test
	public void introspectWhenIntrospectionEndpointThrowsExceptionThenInvalidToken() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			server.setDispatcher(requiresAuth(CLIENT_ID, CLIENT_SECRET, ACTIVE_RESPONSE));
			server.start();
			String introspectUri = server.url("/introspect").toString();
			server.shutdown();
			OpaqueTokenIntrospector introspectionClient = RestClientSpringOpaqueTokenIntrospector
				.withIntrospectionUri(introspectUri)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.build();
			assertThatExceptionOfType(OAuth2IntrospectionException.class)
				.isThrownBy(() -> introspectionClient.introspect("token"));
		}
	}

	@Test
	public void introspectWhenIntrospectionEndpointReturnsMalformedResponseThenInvalidToken() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			server.setDispatcher(requiresAuth(CLIENT_ID, CLIENT_SECRET, "{}"));
			String introspectUri = server.url("/introspect").toString();
			OpaqueTokenIntrospector introspectionClient = RestClientSpringOpaqueTokenIntrospector
				.withIntrospectionUri(introspectUri)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.build();
			assertThatExceptionOfType(OAuth2IntrospectionException.class)
				.isThrownBy(() -> introspectionClient.introspect("token"));
		}
	}

	@Test
	public void introspectWhenIntrospectionTokenReturnsInvalidResponseThenInvalidToken() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			server.setDispatcher(requiresAuth(CLIENT_ID, CLIENT_SECRET, INVALID_RESPONSE));
			String introspectUri = server.url("/introspect").toString();
			OpaqueTokenIntrospector introspectionClient = RestClientSpringOpaqueTokenIntrospector
				.withIntrospectionUri(introspectUri)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.build();
			assertThatExceptionOfType(OAuth2IntrospectionException.class)
				.isThrownBy(() -> introspectionClient.introspect("token"));
		}
	}

	// gh-7563
	@Test
	public void introspectWhenIntrospectionTokenReturnsMalformedScopeThenEmptyAuthorities() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			server.setDispatcher(requiresAuth(CLIENT_ID, CLIENT_SECRET, MALFORMED_SCOPE_RESPONSE));
			String introspectUri = server.url("/introspect").toString();
			OpaqueTokenIntrospector introspectionClient = RestClientSpringOpaqueTokenIntrospector
				.withIntrospectionUri(introspectUri)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.build();
			OAuth2AuthenticatedPrincipal principal = introspectionClient.introspect("token");
			assertThat(principal.getAuthorities()).isEmpty();
			Collection<String> scope = principal.getAttribute("scope");
			assertThat(scope).containsExactly("read", "write", "dolphin");
		}
	}

	// gh-15165
	@Test
	public void introspectWhenActiveThenMapsAuthorities() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			server.setDispatcher(requiresAuth(CLIENT_ID, CLIENT_SECRET, ACTIVE_RESPONSE));
			String introspectUri = server.url("/introspect").toString();
			OpaqueTokenIntrospector introspectionClient = RestClientSpringOpaqueTokenIntrospector
				.withIntrospectionUri(introspectUri)
				.clientId(CLIENT_ID)
				.clientSecret(CLIENT_SECRET)
				.build();
			OAuth2AuthenticatedPrincipal principal = introspectionClient.introspect("token");
			assertThat(principal.getAuthorities()).isNotEmpty();
			Collection<String> scope = principal.getAttribute("scope");
			assertThat(scope).containsExactly("read", "write", "dolphin");
			Collection<String> authorities = AuthorityUtils.authorityListToSet(principal.getAuthorities());
			assertThat(authorities).containsExactly("SCOPE_read", "SCOPE_write", "SCOPE_dolphin");
		}
	}

	@Test
	public void setRequestEntityConverterWhenConverterIsNullThenExceptionIsThrown() {
		RestClient restClient = mock(RestClient.class);
		RestClientSpringOpaqueTokenIntrospector introspectionClient = new RestClientSpringOpaqueTokenIntrospector(
				INTROSPECTION_URL, restClient);
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> introspectionClient.setRequestEntityConverter(null));
	}

	@Test
	public void setAuthenticationConverterWhenConverterIsNullThenExceptionIsThrown() {
		RestClient restClient = mock(RestClient.class);
		RestClientSpringOpaqueTokenIntrospector introspectionClient = new RestClientSpringOpaqueTokenIntrospector(
				INTROSPECTION_URL, restClient);
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> introspectionClient.setAuthenticationConverter(null));
	}

	@Test
	public void introspectWithoutEncodeClientCredentialsThenExceptionIsThrown() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			String response = """
					{
						"active": true,
						"username": "client%&1"
					}
					""";
			server.setDispatcher(requiresAuth("client%25%261", "secret%40%242", response));
			String introspectUri = server.url("/introspect").toString();
			RestClient restClient = RestClient.builder()
				.defaultHeaders((h) -> h.setBasicAuth("client%&1", "secret@$2"))
				.build();
			OpaqueTokenIntrospector introspectionClient = new RestClientSpringOpaqueTokenIntrospector(introspectUri,
					restClient);
			assertThatExceptionOfType(OAuth2IntrospectionException.class)
				.isThrownBy(() -> introspectionClient.introspect("token"));
		}
	}

	@Test
	public void introspectWithEncodeClientCredentialsThenOk() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			String response = """
					{
						"active": true,
						"username": "client&1"
					}
					""";
			server.setDispatcher(requiresAuth("client%261", "secret%40%242", response));
			String introspectUri = server.url("/introspect").toString();
			OpaqueTokenIntrospector introspectionClient = SpringOpaqueTokenIntrospector
				.withIntrospectionUri(introspectUri)
				.clientId("client&1")
				.clientSecret("secret@$2")
				.build();
			OAuth2AuthenticatedPrincipal authority = introspectionClient.introspect("token");
			// @formatter:off
			assertThat(authority.getAttributes())
					.isNotNull()
					.containsEntry(OAuth2TokenIntrospectionClaimNames.ACTIVE, true)
					.containsEntry(OAuth2TokenIntrospectionClaimNames.USERNAME, "client&1");
			// @formatter:on
		}
	}

	private static ResponseEntity<Map<String, Object>> response(String content) {
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		try {
			return new ResponseEntity<>(JSONObjectUtils.parse(content), headers, HttpStatus.OK);
		}
		catch (Exception ex) {
			throw new IllegalArgumentException(ex);
		}
	}

	private static ResponseEntity<Map<String, Object>> response(Map<String, Object> content) {
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		try {
			return new ResponseEntity<>(content, headers, HttpStatus.OK);
		}
		catch (Exception ex) {
			throw new IllegalArgumentException(ex);
		}
	}

	private static Dispatcher requiresAuth(String username, String password, String response) {
		return new Dispatcher() {
			@Override
			public MockResponse dispatch(RecordedRequest request) {
				String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
				// @formatter:off
				return Optional.ofNullable(authorization)
						.filter((a) -> isAuthorized(authorization, username, password))
						.map((a) -> ok(response))
						.orElse(unauthorized());
				// @formatter:on
			}
		};
	}

	private static boolean isAuthorized(String authorization, String username, String password) {
		String[] values = new String(Base64.getDecoder().decode(authorization.substring(6))).split(":");
		return username.equals(values[0]) && password.equals(values[1]);
	}

	private static MockResponse ok(String response) {
		// @formatter:off
		return new MockResponse().setBody(response)
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
		// @formatter:on
	}

	private static MockResponse unauthorized() {
		return new MockResponse().setResponseCode(401);
	}

}
