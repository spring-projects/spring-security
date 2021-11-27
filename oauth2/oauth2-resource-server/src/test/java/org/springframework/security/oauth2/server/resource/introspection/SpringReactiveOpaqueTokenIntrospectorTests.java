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

import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;

/**
 * Tests for {@link SpringReactiveOpaqueTokenIntrospector}
 */
public class SpringReactiveOpaqueTokenIntrospectorTests {

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

	private final ObjectMapper mapper = new ObjectMapper();

	@Test
	public void authenticateWhenActiveTokenThenOk() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			server.setDispatcher(requiresAuth(CLIENT_ID, CLIENT_SECRET, ACTIVE_RESPONSE));
			String introspectUri = server.url("/introspect").toString();
			SpringReactiveOpaqueTokenIntrospector introspectionClient = new SpringReactiveOpaqueTokenIntrospector(
					introspectUri, CLIENT_ID, CLIENT_SECRET);
			OAuth2AuthenticatedPrincipal authority = introspectionClient.introspect("token").block();
			assertThat(authority).isNotNull();
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
	public void authenticateWhenBadClientCredentialsThenAuthenticationException() throws IOException {
		try (MockWebServer server = new MockWebServer()) {
			server.setDispatcher(requiresAuth(CLIENT_ID, CLIENT_SECRET, ACTIVE_RESPONSE));
			String introspectUri = server.url("/introspect").toString();
			SpringReactiveOpaqueTokenIntrospector introspectionClient = new SpringReactiveOpaqueTokenIntrospector(
					introspectUri, CLIENT_ID, "wrong");
			assertThatExceptionOfType(OAuth2IntrospectionException.class)
					.isThrownBy(() -> introspectionClient.introspect("token").block());

		}
	}

	@Test
	public void authenticateWhenInactiveTokenThenInvalidToken() {
		WebClient webClient = mockResponse(INACTIVE_RESPONSE);
		SpringReactiveOpaqueTokenIntrospector introspectionClient = new SpringReactiveOpaqueTokenIntrospector(
				INTROSPECTION_URL, webClient);
		assertThatExceptionOfType(BadOpaqueTokenException.class)
				.isThrownBy(() -> introspectionClient.introspect("token").block())
				.withMessage("Provided token isn't active");
	}

	@Test
	public void authenticateWhenActiveTokenThenParsesValuesInResponse() {
		Map<String, Object> introspectedValues = new HashMap<>();
		introspectedValues.put(OAuth2TokenIntrospectionClaimNames.ACTIVE, true);
		introspectedValues.put(OAuth2TokenIntrospectionClaimNames.AUD, Arrays.asList("aud"));
		introspectedValues.put(OAuth2TokenIntrospectionClaimNames.NBF, 29348723984L);
		WebClient webClient = mockResponse(introspectedValues);
		SpringReactiveOpaqueTokenIntrospector introspectionClient = new SpringReactiveOpaqueTokenIntrospector(
				INTROSPECTION_URL, webClient);
		OAuth2AuthenticatedPrincipal authority = introspectionClient.introspect("token").block();
		assertThat(authority).isNotNull();
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
	public void authenticateWhenIntrospectionEndpointThrowsExceptionThenInvalidToken() {
		WebClient webClient = mockResponse(new IllegalStateException("server was unresponsive"));
		SpringReactiveOpaqueTokenIntrospector introspectionClient = new SpringReactiveOpaqueTokenIntrospector(
				INTROSPECTION_URL, webClient);
		// @formatter:off
		assertThatExceptionOfType(OAuth2IntrospectionException.class)
				.isThrownBy(() -> introspectionClient.introspect("token").block())
				.withMessage("server was unresponsive");
		// @formatter:on
	}

	@Test
	public void authenticateWhenIntrospectionTokenReturnsInvalidResponseThenInvalidToken() {
		WebClient webClient = mockResponse(INVALID_RESPONSE);
		SpringReactiveOpaqueTokenIntrospector introspectionClient = new SpringReactiveOpaqueTokenIntrospector(
				INTROSPECTION_URL, webClient);
		// @formatter:off
		assertThatExceptionOfType(OAuth2IntrospectionException.class)
				.isThrownBy(() -> introspectionClient.introspect("token").block());
		// @formatter:on
	}

	@Test
	public void constructorWhenIntrospectionUriIsEmptyThenIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new SpringReactiveOpaqueTokenIntrospector("", CLIENT_ID, CLIENT_SECRET));
	}

	@Test
	public void constructorWhenClientIdIsEmptyThenIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new SpringReactiveOpaqueTokenIntrospector(INTROSPECTION_URL, "", CLIENT_SECRET));
	}

	@Test
	public void constructorWhenClientSecretIsNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new SpringReactiveOpaqueTokenIntrospector(INTROSPECTION_URL, CLIENT_ID, null));
	}

	@Test
	public void constructorWhenRestOperationsIsNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new SpringReactiveOpaqueTokenIntrospector(INTROSPECTION_URL, null));
	}

	private WebClient mockResponse(String response) {
		return mockResponse(toMap(response));
	}

	private WebClient mockResponse(Map<String, Object> response) {
		WebClient real = WebClient.builder().build();
		WebClient.RequestBodyUriSpec spec = spy(real.post());
		WebClient webClient = spy(WebClient.class);
		given(webClient.post()).willReturn(spec);
		ClientResponse clientResponse = mock(ClientResponse.class);
		given(clientResponse.rawStatusCode()).willReturn(200);
		given(clientResponse.statusCode()).willReturn(HttpStatus.OK);
		given(clientResponse.bodyToMono(STRING_OBJECT_MAP)).willReturn(Mono.just(response));
		ClientResponse.Headers headers = mock(ClientResponse.Headers.class);
		given(headers.contentType()).willReturn(Optional.of(MediaType.APPLICATION_JSON));
		given(clientResponse.headers()).willReturn(headers);
		given(spec.exchange()).willReturn(Mono.just(clientResponse));
		return webClient;
	}

	@SuppressWarnings("unchecked")
	private Map<String, Object> toMap(String string) {
		try {
			return this.mapper.readValue(string, Map.class);
		}
		catch (Exception ex) {
			throw new IllegalArgumentException(ex);
		}
	}

	private WebClient mockResponse(Throwable ex) {
		WebClient real = WebClient.builder().build();
		WebClient.RequestBodyUriSpec spec = spy(real.post());
		WebClient webClient = spy(WebClient.class);
		given(webClient.post()).willReturn(spec);
		given(spec.exchange()).willThrow(ex);
		return webClient;
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
