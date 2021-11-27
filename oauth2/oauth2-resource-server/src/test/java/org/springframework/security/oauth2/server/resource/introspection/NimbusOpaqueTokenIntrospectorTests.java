/*
 * Copyright 2002-2021 the original author or authors.
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
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
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
import static org.assertj.core.api.Assumptions.assumeThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
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
	private static final String MALFORMED_ISSUER_RESPONSE = "{\n"
			+ "     \"active\" : \"true\",\n"
			+ "     \"iss\" : \"badissuer\"\n"
			+ "    }";
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

	private static final ResponseEntity<String> ACTIVE = response(ACTIVE_RESPONSE);

	private static final ResponseEntity<String> INACTIVE = response(INACTIVE_RESPONSE);

	private static final ResponseEntity<String> INVALID = response(INVALID_RESPONSE);

	private static final ResponseEntity<String> MALFORMED_ISSUER = response(MALFORMED_ISSUER_RESPONSE);

	private static final ResponseEntity<String> MALFORMED_SCOPE = response(MALFORMED_SCOPE_RESPONSE);

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
	public void introspectWhenInactiveTokenThenInvalidToken() {
		RestOperations restOperations = mock(RestOperations.class);
		OpaqueTokenIntrospector introspectionClient = new NimbusOpaqueTokenIntrospector(INTROSPECTION_URL,
				restOperations);
		given(restOperations.exchange(any(RequestEntity.class), eq(String.class))).willReturn(INACTIVE);
		// @formatter:off
		assertThatExceptionOfType(OAuth2IntrospectionException.class)
				.isThrownBy(() -> introspectionClient.introspect("token"))
				.withMessage("Provided token isn't active");
		// @formatter:on
	}

	@Test
	public void introspectWhenActiveTokenThenParsesValuesInResponse() {
		Map<String, Object> introspectedValues = new HashMap<>();
		introspectedValues.put(OAuth2TokenIntrospectionClaimNames.ACTIVE, true);
		introspectedValues.put(OAuth2TokenIntrospectionClaimNames.AUD, Arrays.asList("aud"));
		introspectedValues.put(OAuth2TokenIntrospectionClaimNames.NBF, 29348723984L);
		RestOperations restOperations = mock(RestOperations.class);
		OpaqueTokenIntrospector introspectionClient = new NimbusOpaqueTokenIntrospector(INTROSPECTION_URL,
				restOperations);
		given(restOperations.exchange(any(RequestEntity.class), eq(String.class)))
				.willReturn(response(new JSONObject(introspectedValues).toJSONString()));
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

	@Test
	public void introspectWhenIntrospectionEndpointThrowsExceptionThenInvalidToken() {
		RestOperations restOperations = mock(RestOperations.class);
		OpaqueTokenIntrospector introspectionClient = new NimbusOpaqueTokenIntrospector(INTROSPECTION_URL,
				restOperations);
		given(restOperations.exchange(any(RequestEntity.class), eq(String.class)))
				.willThrow(new IllegalStateException("server was unresponsive"));
		// @formatter:off
		assertThatExceptionOfType(OAuth2IntrospectionException.class)
				.isThrownBy(() -> introspectionClient.introspect("token"))
				.withMessage("server was unresponsive");
		// @formatter:on
	}

	@Test
	public void introspectWhenIntrospectionEndpointReturnsMalformedResponseThenInvalidToken() {
		RestOperations restOperations = mock(RestOperations.class);
		OpaqueTokenIntrospector introspectionClient = new NimbusOpaqueTokenIntrospector(INTROSPECTION_URL,
				restOperations);
		given(restOperations.exchange(any(RequestEntity.class), eq(String.class))).willReturn(response("malformed"));
		assertThatExceptionOfType(OAuth2IntrospectionException.class)
				.isThrownBy(() -> introspectionClient.introspect("token"));
	}

	@Test
	public void introspectWhenIntrospectionTokenReturnsInvalidResponseThenInvalidToken() {
		RestOperations restOperations = mock(RestOperations.class);
		OpaqueTokenIntrospector introspectionClient = new NimbusOpaqueTokenIntrospector(INTROSPECTION_URL,
				restOperations);
		given(restOperations.exchange(any(RequestEntity.class), eq(String.class))).willReturn(INVALID);
		assertThatExceptionOfType(OAuth2IntrospectionException.class)
				.isThrownBy(() -> introspectionClient.introspect("token"));
	}

	@Test
	public void introspectWhenIntrospectionTokenReturnsMalformedIssuerResponseThenInvalidToken() {
		RestOperations restOperations = mock(RestOperations.class);
		OpaqueTokenIntrospector introspectionClient = new NimbusOpaqueTokenIntrospector(INTROSPECTION_URL,
				restOperations);
		given(restOperations.exchange(any(RequestEntity.class), eq(String.class))).willReturn(MALFORMED_ISSUER);
		assertThatExceptionOfType(OAuth2IntrospectionException.class)
				.isThrownBy(() -> introspectionClient.introspect("token"));
	}

	// gh-7563
	@Test
	public void introspectWhenIntrospectionTokenReturnsMalformedScopeThenEmptyAuthorities() {
		RestOperations restOperations = mock(RestOperations.class);
		OpaqueTokenIntrospector introspectionClient = new NimbusOpaqueTokenIntrospector(INTROSPECTION_URL,
				restOperations);
		given(restOperations.exchange(any(RequestEntity.class), eq(String.class))).willReturn(MALFORMED_SCOPE);
		OAuth2AuthenticatedPrincipal principal = introspectionClient.introspect("token");
		assertThat(principal.getAuthorities()).isEmpty();
		JSONArray scope = principal.getAttribute("scope");
		assertThat(scope).containsExactly("read", "write", "dolphin");
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
	public void setRequestEntityConverterWhenNonNullConverterGivenThenConverterUsed() {
		RestOperations restOperations = mock(RestOperations.class);
		Converter<String, RequestEntity<?>> requestEntityConverter = mock(Converter.class);
		RequestEntity requestEntity = mock(RequestEntity.class);
		String tokenToIntrospect = "some token";
		given(requestEntityConverter.convert(tokenToIntrospect)).willReturn(requestEntity);
		given(restOperations.exchange(requestEntity, String.class)).willReturn(ACTIVE);
		NimbusOpaqueTokenIntrospector introspectionClient = new NimbusOpaqueTokenIntrospector(INTROSPECTION_URL,
				restOperations);
		introspectionClient.setRequestEntityConverter(requestEntityConverter);
		introspectionClient.introspect(tokenToIntrospect);
		verify(requestEntityConverter).convert(tokenToIntrospect);
	}

	@Test
	public void handleMissingContentType() {
		RestOperations restOperations = mock(RestOperations.class);
		ResponseEntity<String> stubResponse = ResponseEntity.ok(ACTIVE_RESPONSE);
		given(restOperations.exchange(any(RequestEntity.class), eq(String.class))).willReturn(stubResponse);
		OpaqueTokenIntrospector introspectionClient = new NimbusOpaqueTokenIntrospector(INTROSPECTION_URL,
				restOperations);

		// Protect against potential regressions where a default content type might be
		// added by default.
		assumeThat(stubResponse.getHeaders().getContentType()).isNull();

		assertThatExceptionOfType(OAuth2IntrospectionException.class)
				.isThrownBy(() -> introspectionClient.introspect("sometokenhere"));
	}

	@ParameterizedTest(name = "{displayName} when Content-Type={0}")
	@ValueSource(strings = { MediaType.APPLICATION_CBOR_VALUE, MediaType.TEXT_MARKDOWN_VALUE,
			MediaType.APPLICATION_XML_VALUE, MediaType.APPLICATION_OCTET_STREAM_VALUE })
	public void handleNonJsonContentType(String type) {
		RestOperations restOperations = mock(RestOperations.class);
		ResponseEntity<String> stubResponse = ResponseEntity.ok().contentType(MediaType.parseMediaType(type))
				.body(ACTIVE_RESPONSE);
		given(restOperations.exchange(any(RequestEntity.class), eq(String.class))).willReturn(stubResponse);
		OpaqueTokenIntrospector introspectionClient = new NimbusOpaqueTokenIntrospector(INTROSPECTION_URL,
				restOperations);

		assertThatExceptionOfType(OAuth2IntrospectionException.class)
				.isThrownBy(() -> introspectionClient.introspect("sometokenhere"));
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
