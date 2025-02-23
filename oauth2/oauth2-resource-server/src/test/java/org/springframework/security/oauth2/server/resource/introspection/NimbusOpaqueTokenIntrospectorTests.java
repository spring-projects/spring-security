/*
 * Copyright 2002-2025 the original author or authors.
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
import java.util.List;
import java.util.Optional;

import okhttp3.HttpUrl;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.web.client.RestOperations;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link NimbusOpaqueTokenIntrospector}
 */
public class NimbusOpaqueTokenIntrospectorTests {

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
			OpaqueTokenIntrospector introspectionClient = new NimbusOpaqueTokenIntrospector(introspectUri, CLIENT_ID,
					CLIENT_SECRET);
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
			OpaqueTokenIntrospector introspectionClient = new NimbusOpaqueTokenIntrospector(introspectUri, CLIENT_ID,
					"wrong");
			assertThatExceptionOfType(OAuth2IntrospectionException.class)
				.isThrownBy(() -> introspectionClient.introspect("token"));
		}
	}

	@Test
	public void introspectWhenInactiveTokenThenInvalidToken() throws IOException {
		try (MockWebServer server = new MockWebServer()) {
			server.setDispatcher(requiresAuth(CLIENT_ID, CLIENT_SECRET, INACTIVE_RESPONSE));
			String introspectUri = server.url("/introspect").toString();
			OpaqueTokenIntrospector introspectionClient = new NimbusOpaqueTokenIntrospector(introspectUri, CLIENT_ID,
					CLIENT_SECRET);
			// @formatter:off
			assertThatExceptionOfType(OAuth2IntrospectionException.class)
					.isThrownBy(() -> introspectionClient.introspect("token"))
					.withMessage("Provided token isn't active");
			// @formatter:on
		}
	}

	@Test
	public void introspectWhenActiveTokenThenParsesValuesInResponse() throws IOException {
		try (MockWebServer server = new MockWebServer()) {
			String introspectedValues = """
					{
						"active": true,
						"aud": "aud",
						"nbf": 29348723984
					}
					""";
			server.setDispatcher(requiresAuth(CLIENT_ID, CLIENT_SECRET, introspectedValues));
			String introspectUri = server.url("/introspect").toString();
			OpaqueTokenIntrospector introspectionClient = new NimbusOpaqueTokenIntrospector(introspectUri, CLIENT_ID,
					CLIENT_SECRET);
			OAuth2AuthenticatedPrincipal authority = introspectionClient.introspect("token");
			// @formatter:off
			assertThat(authority.getAttributes())
					.isNotNull()
					.containsEntry(OAuth2TokenIntrospectionClaimNames.ACTIVE, true)
					.containsEntry(OAuth2TokenIntrospectionClaimNames.AUD, Arrays.asList("aud"))
					.containsEntry(OAuth2TokenIntrospectionClaimNames.NBF, Instant.ofEpochSecond(29348723984L))
					.doesNotContainKey(OAuth2TokenIntrospectionClaimNames.CLIENT_ID)
					.doesNotContainKey(OAuth2TokenIntrospectionClaimNames.SCOPE);
			// @formatter:on
		}
	}

	@Test
	public void introspectWhenIntrospectionEndpointThrowsExceptionThenInvalidToken() throws IOException {
		try (MockWebServer server = new MockWebServer()) {
			server.setDispatcher(new Dispatcher() {
				@Override
				public MockResponse dispatch(final RecordedRequest request) {
					return new MockResponse().setResponseCode(500);
				}
			});
			String introspectUri = server.url("/introspect").toString();
			OpaqueTokenIntrospector introspectionClient = new NimbusOpaqueTokenIntrospector(introspectUri, CLIENT_ID,
					CLIENT_SECRET);
			// @formatter:off
			assertThatExceptionOfType(OAuth2IntrospectionException.class)
					.isThrownBy(() -> introspectionClient.introspect("token"))
					.withMessageContaining("500");
			// @formatter:on
		}
	}

	@Test
	public void introspectWhenIntrospectionEndpointReturnsMalformedResponseThenInvalidToken() throws IOException {
		try (MockWebServer server = new MockWebServer()) {
			server.setDispatcher(requiresAuth(CLIENT_ID, CLIENT_SECRET, "malformed"));
			String introspectUri = server.url("/introspect").toString();
			OpaqueTokenIntrospector introspectionClient = new NimbusOpaqueTokenIntrospector(introspectUri, CLIENT_ID,
					CLIENT_SECRET);
			assertThatExceptionOfType(OAuth2IntrospectionException.class)
				.isThrownBy(() -> introspectionClient.introspect("token"));
		}
	}

	@Test
	public void introspectWhenIntrospectionTokenReturnsInvalidResponseThenInvalidToken() throws IOException {
		try (MockWebServer server = new MockWebServer()) {
			server.setDispatcher(requiresAuth(CLIENT_ID, CLIENT_SECRET, INVALID_RESPONSE));
			String introspectUri = server.url("/introspect").toString();
			OpaqueTokenIntrospector introspectionClient = new NimbusOpaqueTokenIntrospector(introspectUri, CLIENT_ID,
					CLIENT_SECRET);
			assertThatExceptionOfType(OAuth2IntrospectionException.class)
				.isThrownBy(() -> introspectionClient.introspect("token"));
		}
	}

	// gh-7563
	@Test
	public void introspectWhenIntrospectionTokenReturnsMalformedScopeThenEmptyAuthorities() throws IOException {
		try (MockWebServer server = new MockWebServer()) {
			server.setDispatcher(requiresAuth(CLIENT_ID, CLIENT_SECRET, MALFORMED_SCOPE_RESPONSE));
			String introspectUri = server.url("/introspect").toString();
			OpaqueTokenIntrospector introspectionClient = new NimbusOpaqueTokenIntrospector(introspectUri, CLIENT_ID,
					CLIENT_SECRET);
			OAuth2AuthenticatedPrincipal principal = introspectionClient.introspect("token");
			assertThat(principal.getAuthorities()).isEmpty();
			List<String> scope = principal.getAttribute("scope");
			assertThat(scope).containsExactly("read", "write", "dolphin");
		}
	}

	@Test
	public void constructorWhenIntrospectionUriIsNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new NimbusOpaqueTokenIntrospector(null, CLIENT_ID, CLIENT_SECRET));
	}

	@Test
	public void constructorWhenClientIdIsNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new NimbusOpaqueTokenIntrospector(INTROSPECTION_URL, null, CLIENT_SECRET));
	}

	@Test
	public void constructorWhenClientSecretIsNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new NimbusOpaqueTokenIntrospector(INTROSPECTION_URL, CLIENT_ID, null));
	}

	@Test
	public void constructorWhenRestOperationsIsNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new NimbusOpaqueTokenIntrospector(INTROSPECTION_URL, null));
	}

	@Test
	public void setRequestEntityConverterWhenConverterIsNullThenExceptionIsThrown() {
		RestOperations restOperations = mock(RestOperations.class);
		NimbusOpaqueTokenIntrospector introspectionClient = new NimbusOpaqueTokenIntrospector(INTROSPECTION_URL,
				restOperations);
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> introspectionClient.setRequestEntityConverter(null));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void setRequestEntityConverterWhenNonNullConverterGivenThenConverterUsed() throws IOException {
		try (MockWebServer server = new MockWebServer()) {
			server.setDispatcher(requiresAuth(CLIENT_ID, CLIENT_SECRET, ACTIVE_RESPONSE));
			HttpUrl introspectUri = server.url("/introspect");
			Converter<String, RequestEntity<?>> requestEntityConverter = mock(Converter.class);
			RequestEntity requestEntity = new RequestEntity<>(HttpHeaders.EMPTY, HttpMethod.POST, introspectUri.uri());
			String tokenToIntrospect = "some token";
			given(requestEntityConverter.convert(tokenToIntrospect)).willReturn(requestEntity);
			NimbusOpaqueTokenIntrospector introspectionClient = new NimbusOpaqueTokenIntrospector(
					introspectUri.toString(), CLIENT_ID, CLIENT_SECRET);
			introspectionClient.setRequestEntityConverter(requestEntityConverter);
			introspectionClient.introspect(tokenToIntrospect);
			verify(requestEntityConverter).convert(tokenToIntrospect);
		}
	}

	@Test
	public void handleMissingContentType() throws IOException {
		try (MockWebServer server = new MockWebServer()) {
			server.setDispatcher(new Dispatcher() {
				@Override
				public MockResponse dispatch(final RecordedRequest request) {
					return ok(ACTIVE_RESPONSE).removeHeader(HttpHeaders.CONTENT_TYPE);
				}
			});
			String introspectUri = server.url("/introspect").toString();
			OpaqueTokenIntrospector introspectionClient = new NimbusOpaqueTokenIntrospector(introspectUri, CLIENT_ID,
					CLIENT_SECRET);

			assertThatExceptionOfType(OAuth2IntrospectionException.class)
				.isThrownBy(() -> introspectionClient.introspect("sometokenhere"));
		}
	}

	@ParameterizedTest(name = "{displayName} when Content-Type={0}")
	@ValueSource(strings = { MediaType.APPLICATION_CBOR_VALUE, MediaType.TEXT_MARKDOWN_VALUE,
			MediaType.APPLICATION_XML_VALUE, MediaType.APPLICATION_OCTET_STREAM_VALUE })
	public void handleNonJsonContentType(String type) throws IOException {
		try (MockWebServer server = new MockWebServer()) {
			server.setDispatcher(new Dispatcher() {
				@Override
				public MockResponse dispatch(final RecordedRequest request) {
					return ok(ACTIVE_RESPONSE).setHeader(HttpHeaders.CONTENT_TYPE, type);
				}
			});
			String introspectUri = server.url("/introspect").toString();
			OpaqueTokenIntrospector introspectionClient = new NimbusOpaqueTokenIntrospector(introspectUri, CLIENT_ID,
					CLIENT_SECRET);

			assertThatExceptionOfType(OAuth2IntrospectionException.class)
				.isThrownBy(() -> introspectionClient.introspect("sometokenhere"));
		}
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
