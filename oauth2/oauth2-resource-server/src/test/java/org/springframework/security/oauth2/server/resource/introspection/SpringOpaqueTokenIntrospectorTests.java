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
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import com.nimbusds.jose.util.JSONObjectUtils;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.Test;

import org.springframework.core.ParameterizedTypeReference;
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link SpringOpaqueTokenIntrospector}
 */
public class SpringOpaqueTokenIntrospectorTests {

	private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<Map<String, Object>>() {
	};

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

	private static final ResponseEntity<Map<String, Object>> ACTIVE = response(ACTIVE_RESPONSE);

	private static final ResponseEntity<Map<String, Object>> INACTIVE = response(INACTIVE_RESPONSE);

	private static final ResponseEntity<Map<String, Object>> INVALID = response(INVALID_RESPONSE);

	private static final ResponseEntity<Map<String, Object>> MALFORMED_SCOPE = response(MALFORMED_SCOPE_RESPONSE);

	@Test
	public void introspectWhenActiveTokenThenOk() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			server.setDispatcher(requiresAuth(CLIENT_ID, CLIENT_SECRET, ACTIVE_RESPONSE));
			String introspectUri = server.url("/introspect").toString();
			OpaqueTokenIntrospector introspectionClient = new SpringOpaqueTokenIntrospector(introspectUri, CLIENT_ID,
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
			OpaqueTokenIntrospector introspectionClient = new SpringOpaqueTokenIntrospector(introspectUri, CLIENT_ID,
					"wrong");
			assertThatExceptionOfType(OAuth2IntrospectionException.class)
					.isThrownBy(() -> introspectionClient.introspect("token"));
		}
	}

	@Test
	public void introspectWhenInactiveTokenThenInvalidToken() {
		RestOperations restOperations = mock(RestOperations.class);
		OpaqueTokenIntrospector introspectionClient = new SpringOpaqueTokenIntrospector(INTROSPECTION_URL,
				restOperations);
		given(restOperations.exchange(any(RequestEntity.class), eq(STRING_OBJECT_MAP))).willReturn(INACTIVE);
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
		OpaqueTokenIntrospector introspectionClient = new SpringOpaqueTokenIntrospector(INTROSPECTION_URL,
				restOperations);
		given(restOperations.exchange(any(RequestEntity.class), eq(STRING_OBJECT_MAP)))
				.willReturn(response(introspectedValues));
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
		OpaqueTokenIntrospector introspectionClient = new SpringOpaqueTokenIntrospector(INTROSPECTION_URL,
				restOperations);
		given(restOperations.exchange(any(RequestEntity.class), eq(STRING_OBJECT_MAP)))
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
		OpaqueTokenIntrospector introspectionClient = new SpringOpaqueTokenIntrospector(INTROSPECTION_URL,
				restOperations);
		given(restOperations.exchange(any(RequestEntity.class), eq(STRING_OBJECT_MAP))).willReturn(response("{}"));
		assertThatExceptionOfType(OAuth2IntrospectionException.class)
				.isThrownBy(() -> introspectionClient.introspect("token"));
	}

	@Test
	public void introspectWhenIntrospectionTokenReturnsInvalidResponseThenInvalidToken() {
		RestOperations restOperations = mock(RestOperations.class);
		OpaqueTokenIntrospector introspectionClient = new SpringOpaqueTokenIntrospector(INTROSPECTION_URL,
				restOperations);
		given(restOperations.exchange(any(RequestEntity.class), eq(STRING_OBJECT_MAP))).willReturn(INVALID);
		assertThatExceptionOfType(OAuth2IntrospectionException.class)
				.isThrownBy(() -> introspectionClient.introspect("token"));
	}

	// gh-7563
	@Test
	public void introspectWhenIntrospectionTokenReturnsMalformedScopeThenEmptyAuthorities() {
		RestOperations restOperations = mock(RestOperations.class);
		OpaqueTokenIntrospector introspectionClient = new SpringOpaqueTokenIntrospector(INTROSPECTION_URL,
				restOperations);
		given(restOperations.exchange(any(RequestEntity.class), eq(STRING_OBJECT_MAP))).willReturn(MALFORMED_SCOPE);
		OAuth2AuthenticatedPrincipal principal = introspectionClient.introspect("token");
		assertThat(principal.getAuthorities()).isEmpty();
		Collection<String> scope = principal.getAttribute("scope");
		assertThat(scope).containsExactly("read", "write", "dolphin");
	}

	@Test
	public void constructorWhenIntrospectionUriIsNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new SpringOpaqueTokenIntrospector(null, CLIENT_ID, CLIENT_SECRET));
	}

	@Test
	public void constructorWhenClientIdIsNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new SpringOpaqueTokenIntrospector(INTROSPECTION_URL, null, CLIENT_SECRET));
	}

	@Test
	public void constructorWhenClientSecretIsNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new SpringOpaqueTokenIntrospector(INTROSPECTION_URL, CLIENT_ID, null));
	}

	@Test
	public void constructorWhenRestOperationsIsNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new SpringOpaqueTokenIntrospector(INTROSPECTION_URL, null));
	}

	@Test
	public void setRequestEntityConverterWhenConverterIsNullThenExceptionIsThrown() {
		RestOperations restOperations = mock(RestOperations.class);
		SpringOpaqueTokenIntrospector introspectionClient = new SpringOpaqueTokenIntrospector(INTROSPECTION_URL,
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
		given(restOperations.exchange(requestEntity, STRING_OBJECT_MAP)).willReturn(ACTIVE);
		SpringOpaqueTokenIntrospector introspectionClient = new SpringOpaqueTokenIntrospector(INTROSPECTION_URL,
				restOperations);
		introspectionClient.setRequestEntityConverter(requestEntityConverter);
		introspectionClient.introspect(tokenToIntrospect);
		verify(requestEntityConverter).convert(tokenToIntrospect);
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
