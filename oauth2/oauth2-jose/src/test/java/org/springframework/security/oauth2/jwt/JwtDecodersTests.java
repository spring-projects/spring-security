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

package org.springframework.security.oauth2.jwt;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.HttpUrl;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.util.UriComponentsBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

/**
 * Tests for {@link JwtDecoders}
 *
 * @author Josh Cummings
 * @author Rafiullah Hamedy
 */
public class JwtDecodersTests {

	/**
	 * Contains those parameters required to construct a JwtDecoder as well as any
	 * required parameters
	 */
	// @formatter:off
	private static final String DEFAULT_RESPONSE_TEMPLATE = "{\n"
			+ "    \"authorization_endpoint\": \"https://example.com/o/oauth2/v2/auth\", \n"
			+ "    \"id_token_signing_alg_values_supported\": [\n"
			+ "        \"RS256\"\n"
			+ "    ], \n"
			+ "    \"issuer\": \"%s\", \n"
			+ "    \"jwks_uri\": \"%s/.well-known/jwks.json\", \n"
			+ "    \"response_types_supported\": [\n"
			+ "        \"code\", \n"
			+ "        \"token\", \n"
			+ "        \"id_token\", \n"
			+ "        \"code token\", \n"
			+ "        \"code id_token\", \n"
			+ "        \"token id_token\", \n"
			+ "        \"code token id_token\", \n"
			+ "        \"none\"\n"
			+ "    ], \n"
			+ "    \"subject_types_supported\": [\n"
			+ "        \"public\"\n"
			+ "    ], \n"
			+ "    \"token_endpoint\": \"https://example.com/oauth2/v4/token\"\n"
			+ "}";
	// @formatter:on

	private static final String JWK_SET = "{\"keys\":[{\"kty\":\"RSA\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"one\",\"n\":\"oXJ8OyOv_eRnce4akdanR4KYRfnC2zLV4uYNQpcFn6oHL0dj7D6kxQmsXoYgJV8ZVDn71KGmuLvolxsDncc2UrhyMBY6DVQVgMSVYaPCTgW76iYEKGgzTEw5IBRQL9w3SRJWd3VJTZZQjkXef48Ocz06PGF3lhbz4t5UEZtdF4rIe7u-977QwHuh7yRPBQ3sII-cVoOUMgaXB9SHcGF2iZCtPzL_IffDUcfhLQteGebhW8A6eUHgpD5A1PQ-JCw_G7UOzZAjjDjtNM2eqm8j-Ms_gqnm4MiCZ4E-9pDN77CAAPVN7kuX6ejs9KBXpk01z48i9fORYk9u7rAkh1HuQw\"}]}";

	private static final String ISSUER_MISMATCH = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvd3Jvbmdpc3N1ZXIiLCJleHAiOjQ2ODcyNTYwNDl9.Ax8LMI6rhB9Pv_CE3kFi1JPuLj9gZycifWrLeDpkObWEEVAsIls9zAhNFyJlG-Oo7up6_mDhZgeRfyKnpSF5GhKJtXJDCzwg0ZDVUE6rS0QadSxsMMGbl7c4y0lG_7TfLX2iWeNJukJj_oSW9KzW4FsBp1BoocWjrreesqQU3fZHbikH-c_Fs2TsAIpHnxflyEzfOFWpJ8D4DtzHXqfvieMwpy42xsPZK3LR84zlasf0Ne1tC_hLHvyHRdAXwn0CMoKxc7-8j0r9Mq8kAzUsPn9If7bMLqGkxUcTPdk5x7opAUajDZx95SXHLmtztNtBa2S6EfPJXuPKG6tM5Wq5Ug";

	private static final String OIDC_METADATA_PATH = "/.well-known/openid-configuration";

	private static final String OAUTH_METADATA_PATH = "/.well-known/oauth-authorization-server";

	private MockWebServer server;

	private String issuer;

	@BeforeEach
	public void setup() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
		this.issuer = createIssuerFromServer() + "path";
	}

	@AfterEach
	public void cleanup() throws Exception {
		this.server.shutdown();
	}

	@Test
	public void issuerWhenResponseIsTypicalThenReturnedDecoderValidatesIssuer() {
		prepareConfigurationResponse();
		JwtDecoder decoder = JwtDecoders.fromOidcIssuerLocation(this.issuer);
		// @formatter:off
		assertThatExceptionOfType(JwtValidationException.class)
				.isThrownBy(() -> decoder.decode(ISSUER_MISMATCH))
				.withMessageContaining("The iss claim is not valid");
		// @formatter:on
	}

	@Test
	public void issuerWhenOidcFallbackResponseIsTypicalThenReturnedDecoderValidatesIssuer() {
		prepareConfigurationResponseOidc();
		JwtDecoder decoder = JwtDecoders.fromIssuerLocation(this.issuer);
		// @formatter:off
		assertThatExceptionOfType(JwtValidationException.class)
				.isThrownBy(() -> decoder.decode(ISSUER_MISMATCH))
				.withMessageContaining("The iss claim is not valid");
		// @formatter:on
	}

	@Test
	public void issuerWhenOAuth2ResponseIsTypicalThenReturnedDecoderValidatesIssuer() {
		prepareConfigurationResponseOAuth2();
		JwtDecoder decoder = JwtDecoders.fromIssuerLocation(this.issuer);
		// @formatter:off
		assertThatExceptionOfType(JwtValidationException.class)
				.isThrownBy(() -> decoder.decode(ISSUER_MISMATCH))
				.withMessageContaining("The iss claim is not valid");
		// @formatter:on
	}

	@Test
	public void issuerWhenContainsTrailingSlashThenSuccess() {
		this.issuer += "/";
		prepareConfigurationResponse();
		JwtDecoder jwtDecoder = JwtDecoders.fromOidcIssuerLocation(this.issuer);
		assertThat(jwtDecoder).isNotNull();
		assertThat(this.issuer).endsWith("/");
	}

	@Test
	public void issuerWhenOidcFallbackContainsTrailingSlashThenSuccess() {
		this.issuer += "/";
		prepareConfigurationResponseOidc();
		JwtDecoder jwtDecoder = JwtDecoders.fromIssuerLocation(this.issuer);
		assertThat(jwtDecoder).isNotNull();
		assertThat(this.issuer).endsWith("/");
	}

	@Test
	public void issuerWhenOAuth2ContainsTrailingSlashThenSuccess() {
		this.issuer += "/";
		prepareConfigurationResponseOAuth2();
		JwtDecoder jwtDecoder = JwtDecoders.fromIssuerLocation(this.issuer);
		assertThat(jwtDecoder).isNotNull();
		assertThat(this.issuer).endsWith("/");
	}

	@Test
	public void issuerWhenResponseIsNonCompliantThenThrowsRuntimeException() {
		prepareConfigurationResponse("{ \"missing_required_keys\" : \"and_values\" }");
		assertThatExceptionOfType(RuntimeException.class)
			.isThrownBy(() -> JwtDecoders.fromOidcIssuerLocation(this.issuer));
	}

	@Test
	public void issuerWhenOidcFallbackResponseIsNonCompliantThenThrowsRuntimeException() {
		prepareConfigurationResponseOidc("{ \"missing_required_keys\" : \"and_values\" }");
		// @formatter:off
		assertThatExceptionOfType(RuntimeException.class)
				.isThrownBy(() -> JwtDecoders.fromIssuerLocation(this.issuer));
		// @formatter:on
	}

	@Test
	public void issuerWhenOAuth2ResponseIsNonCompliantThenThrowsRuntimeException() {
		prepareConfigurationResponseOAuth2("{ \"missing_required_keys\" : \"and_values\" }");
		// @formatter:off
		assertThatExceptionOfType(RuntimeException.class)
				.isThrownBy(() -> JwtDecoders.fromIssuerLocation(this.issuer));
		// @formatter:on
	}

	// gh-7512
	@Test
	public void issuerWhenResponseDoesNotContainJwksUriThenThrowsIllegalArgumentException()
			throws JsonMappingException, JsonProcessingException {
		prepareConfigurationResponse(this.buildResponseWithMissingJwksUri());
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> JwtDecoders.fromOidcIssuerLocation(this.issuer))
				.withMessage("The public JWK set URI must not be null");
		// @formatter:on
	}

	// gh-7512
	@Test
	public void issuerWhenOidcFallbackResponseDoesNotContainJwksUriThenThrowsIllegalArgumentException()
			throws JsonMappingException, JsonProcessingException {
		prepareConfigurationResponseOidc(this.buildResponseWithMissingJwksUri());
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> JwtDecoders.fromIssuerLocation(this.issuer))
				.isInstanceOf(IllegalArgumentException.class)
				.withMessage("The public JWK set URI must not be null");
		// @formatter:on
	}

	// gh-7512
	@Test
	public void issuerWhenOAuth2ResponseDoesNotContainJwksUriThenThrowsIllegalArgumentException()
			throws JsonMappingException, JsonProcessingException {
		prepareConfigurationResponseOAuth2(this.buildResponseWithMissingJwksUri());
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> JwtDecoders.fromIssuerLocation(this.issuer))
				.withMessage("The public JWK set URI must not be null");
		// @formatter:on
	}

	@Test
	public void issuerWhenResponseIsMalformedThenThrowsRuntimeException() {
		prepareConfigurationResponse("malformed");
		// @formatter:off
		assertThatExceptionOfType(RuntimeException.class)
				.isThrownBy(() -> JwtDecoders.fromOidcIssuerLocation(this.issuer));
		// @formatter:on
	}

	@Test
	public void issuerWhenOidcFallbackResponseIsMalformedThenThrowsRuntimeException() {
		prepareConfigurationResponseOidc("malformed");
		// @formatter:off
		assertThatExceptionOfType(RuntimeException.class)
				.isThrownBy(() -> JwtDecoders.fromIssuerLocation(this.issuer));
		// @formatter:on
	}

	@Test
	public void issuerWhenOAuth2ResponseIsMalformedThenThrowsRuntimeException() {
		prepareConfigurationResponseOAuth2("malformed");
		// @formatter:off
		assertThatExceptionOfType(RuntimeException.class)
				.isThrownBy(() -> JwtDecoders.fromIssuerLocation(this.issuer));
		// @formatter:on
	}

	@Test
	public void issuerWhenRespondingIssuerMismatchesRequestedIssuerThenThrowsIllegalStateException() {
		prepareConfigurationResponse(String.format(DEFAULT_RESPONSE_TEMPLATE, this.issuer + "/wrong", this.issuer));
		// @formatter:off
		assertThatIllegalStateException()
				.isThrownBy(() -> JwtDecoders.fromOidcIssuerLocation(this.issuer));
		// @formatter:on
	}

	@Test
	public void issuerWhenOidcFallbackRespondingIssuerMismatchesRequestedIssuerThenThrowsIllegalStateException() {
		prepareConfigurationResponseOidc(String.format(DEFAULT_RESPONSE_TEMPLATE, this.issuer + "/wrong", this.issuer));
		// @formatter:off
		assertThatIllegalStateException()
				.isThrownBy(() -> JwtDecoders.fromIssuerLocation(this.issuer));
		// @formatter:on
	}

	@Test
	public void issuerWhenOAuth2RespondingIssuerMismatchesRequestedIssuerThenThrowsIllegalStateException() {
		prepareConfigurationResponseOAuth2(
				String.format(DEFAULT_RESPONSE_TEMPLATE, this.issuer + "/wrong", this.issuer));
		// @formatter:off
		assertThatIllegalStateException()
				.isThrownBy(() -> JwtDecoders.fromIssuerLocation(this.issuer));
		// @formatter:on
	}

	@Test
	public void issuerWhenRequestedIssuerIsUnresponsiveThenThrowsIllegalArgumentException() throws Exception {
		this.server.shutdown();
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> JwtDecoders.fromOidcIssuerLocation("https://issuer"));
		// @formatter:on
	}

	@Test
	public void issuerWhenOidcFallbackRequestedIssuerIsUnresponsiveThenThrowsIllegalArgumentException()
			throws Exception {
		this.server.shutdown();
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> JwtDecoders.fromIssuerLocation("https://issuer"));
		// @formatter:on
	}

	private void prepareConfigurationResponse() {
		String body = String.format(DEFAULT_RESPONSE_TEMPLATE, this.issuer, this.issuer);
		prepareConfigurationResponse(body);
	}

	private void prepareConfigurationResponse(String body) {
		this.server.enqueue(response(body));
		this.server.enqueue(response(JWK_SET));
	}

	private void prepareConfigurationResponseOidc() {
		String body = String.format(DEFAULT_RESPONSE_TEMPLATE, this.issuer, this.issuer);
		prepareConfigurationResponseOidc(body);
	}

	private void prepareConfigurationResponseOidc(String body) {
		Map<String, MockResponse> responses = new HashMap<>();
		responses.put(oidc(), response(body));
		responses.put(jwks(), response(JWK_SET));
		prepareConfigurationResponses(responses);
	}

	private void prepareConfigurationResponseOAuth2() {
		String body = String.format(DEFAULT_RESPONSE_TEMPLATE, this.issuer, this.issuer);
		prepareConfigurationResponseOAuth2(body);
	}

	private void prepareConfigurationResponseOAuth2(String body) {
		Map<String, MockResponse> responses = new HashMap<>();
		responses.put(oauth(), response(body));
		responses.put(jwks(), response(JWK_SET));
		prepareConfigurationResponses(responses);
	}

	private void prepareConfigurationResponses(Map<String, MockResponse> responses) {
		Dispatcher dispatcher = new Dispatcher() {
			@Override
			public MockResponse dispatch(RecordedRequest request) {
				// @formatter:off
				return Optional.of(request)
					.map(RecordedRequest::getRequestUrl)
					.map(HttpUrl::toString)
					.map(responses::get)
					.orElse(new MockResponse().setResponseCode(404));
				// @formatter:on
			}
		};
		this.server.setDispatcher(dispatcher);
	}

	private String createIssuerFromServer() {
		return this.server.url("").toString();
	}

	private String oidc() {
		URI uri = URI.create(this.issuer);
		// @formatter:off
		return UriComponentsBuilder.fromUri(uri)
				.replacePath(uri.getPath() + OIDC_METADATA_PATH)
				.toUriString();
		// @formatter:on
	}

	private String oauth() {
		URI uri = URI.create(this.issuer);
		// @formatter:off
		return UriComponentsBuilder.fromUri(uri)
				.replacePath(OAUTH_METADATA_PATH + uri.getPath())
				.toUriString();
		// @formatter:on
	}

	private String jwks() {
		return this.issuer + "/.well-known/jwks.json";
	}

	private MockResponse response(String body) {
		// @formatter:off
		return new MockResponse()
				.setBody(body)
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
		// @formatter:on
	}

	public String buildResponseWithMissingJwksUri() throws JsonMappingException, JsonProcessingException {
		ObjectMapper mapper = new ObjectMapper();
		Map<String, Object> response = mapper.readValue(DEFAULT_RESPONSE_TEMPLATE,
				new TypeReference<Map<String, Object>>() {
				});
		response.remove("jwks_uri");
		return mapper.writeValueAsString(response);
	}

}
