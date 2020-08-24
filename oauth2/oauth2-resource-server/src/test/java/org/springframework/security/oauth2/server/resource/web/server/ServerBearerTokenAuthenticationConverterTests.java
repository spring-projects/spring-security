/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.oauth2.server.resource.web.server;

import java.util.Base64;

import org.junit.Before;
import org.junit.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrorCodes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author Rob Winch
 * @since 5.1
 */
public class ServerBearerTokenAuthenticationConverterTests {

	private static final String CUSTOM_HEADER = "custom-header";

	private static final String TEST_TOKEN = "test-token";

	private ServerBearerTokenAuthenticationConverter converter;

	@Before
	public void setup() {
		this.converter = new ServerBearerTokenAuthenticationConverter();
	}

	@Test
	public void resolveWhenValidHeaderIsPresentThenTokenIsResolved() {
		// @formatter:off
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + TEST_TOKEN);
		// @formatter:on
		assertThat(convertToToken(request).getToken()).isEqualTo(TEST_TOKEN);
	}

	// gh-8502
	@Test
	public void resolveWhenHeaderEndsWithPaddingIndicatorThenTokenIsResolved() {
		String token = TEST_TOKEN + "==";
		// @formatter:off
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + token);
		// @formatter:on
		assertThat(convertToToken(request).getToken()).isEqualTo(token);
	}

	@Test
	public void resolveWhenCustomDefinedHeaderIsValidAndPresentThenTokenIsResolved() {
		this.converter.setBearerTokenHeaderName(CUSTOM_HEADER);
		// @formatter:off
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/")
				.header(CUSTOM_HEADER, "Bearer " + TEST_TOKEN);
		// @formatter:on
		assertThat(convertToToken(request).getToken()).isEqualTo(TEST_TOKEN);
	}

	// gh-7011
	@Test
	public void resolveWhenValidHeaderIsEmptyStringThenTokenIsResolved() {
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION,
				"Bearer ");
		// @formatter:off
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> convertToToken(request))
				.satisfies((ex) -> {
					BearerTokenError error = (BearerTokenError) ex.getError();
					assertThat(error.getErrorCode()).isEqualTo(BearerTokenErrorCodes.INVALID_TOKEN);
					assertThat(error.getUri()).isEqualTo("https://tools.ietf.org/html/rfc6750#section-3.1");
					assertThat(error.getHttpStatus()).isEqualTo(HttpStatus.UNAUTHORIZED);
				});
		// @formatter:on
	}

	@Test
	public void resolveWhenLowercaseHeaderIsPresentThenTokenIsResolved() {
		// @formatter:off
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/")
				.header(HttpHeaders.AUTHORIZATION, "bearer " + TEST_TOKEN);
		// @formatter:on
		assertThat(convertToToken(request).getToken()).isEqualTo(TEST_TOKEN);
	}

	@Test
	public void resolveWhenNoHeaderIsPresentThenTokenIsNotResolved() {
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/");
		assertThat(convertToToken(request)).isNull();
	}

	@Test
	public void resolveWhenHeaderWithWrongSchemeIsPresentThenTokenIsNotResolved() {
		// @formatter:off
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/")
				.header(HttpHeaders.AUTHORIZATION,
						"Basic " + Base64.getEncoder().encodeToString("test:test".getBytes()));
		// @formatter:on
		assertThat(convertToToken(request)).isNull();
	}

	@Test
	public void resolveWhenHeaderWithMissingTokenIsPresentThenAuthenticationExceptionIsThrown() {
		// @formatter:off
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/")
				.header(HttpHeaders.AUTHORIZATION, "Bearer ");
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> convertToToken(request))
				.withMessageContaining(("Bearer token is malformed"));
		// @formatter:on
	}

	@Test
	public void resolveWhenHeaderWithInvalidCharactersIsPresentThenAuthenticationExceptionIsThrown() {
		// @formatter:off
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/")
				.header(HttpHeaders.AUTHORIZATION, "Bearer an\"invalid\"token");
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> convertToToken(request))
				.withMessageContaining(("Bearer token is malformed"));
		// @formatter:on
	}

	// gh-8865
	@Test
	public void resolveWhenHeaderWithInvalidCharactersIsPresentAndNotSubscribedThenNoneExceptionIsThrown() {
		// @formatter:off
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/")
				.header(HttpHeaders.AUTHORIZATION, "Bearer an\"invalid\"token");
		// @formatter:on
		this.converter.convert(MockServerWebExchange.from(request));
	}

	@Test
	public void resolveWhenValidHeaderIsPresentTogetherWithQueryParameterThenAuthenticationExceptionIsThrown() {
		// @formatter:off
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/")
				.queryParam("access_token", TEST_TOKEN)
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + TEST_TOKEN);
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> convertToToken(request))
				.withMessageContaining("Found multiple bearer tokens in the request");
		// @formatter:on
	}

	@Test
	public void resolveWhenQueryParameterIsPresentAndSupportedThenTokenIsResolved() {
		this.converter.setAllowUriQueryParameter(true);
		// @formatter:off
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/")
				.queryParam("access_token", TEST_TOKEN);
		// @formatter:on
		assertThat(convertToToken(request).getToken()).isEqualTo(TEST_TOKEN);
	}

	// gh-7011
	@Test
	public void resolveWhenQueryParameterIsEmptyAndSupportedThenOAuth2AuthenticationException() {
		this.converter.setAllowUriQueryParameter(true);
		// @formatter:off
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/")
				.queryParam("access_token", "");
		assertThatExceptionOfType(OAuth2AuthenticationException.class)
				.isThrownBy(() -> convertToToken(request))
				.satisfies((ex) -> {
					BearerTokenError error = (BearerTokenError) ex.getError();
					assertThat(error.getErrorCode()).isEqualTo(BearerTokenErrorCodes.INVALID_TOKEN);
					assertThat(error.getUri()).isEqualTo("https://tools.ietf.org/html/rfc6750#section-3.1");
					assertThat(error.getHttpStatus()).isEqualTo(HttpStatus.UNAUTHORIZED);
				});
		// @formatter:on
	}

	@Test
	public void resolveWhenQueryParameterIsPresentAndNotSupportedThenTokenIsNotResolved() {
		// @formatter:off
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest.get("/")
				.queryParam("access_token", TEST_TOKEN);
		// @formatter:on
		assertThat(convertToToken(request)).isNull();
	}

	private BearerTokenAuthenticationToken convertToToken(MockServerHttpRequest.BaseBuilder<?> request) {
		return convertToToken(request.build());
	}

	private BearerTokenAuthenticationToken convertToToken(MockServerHttpRequest request) {
		MockServerWebExchange exchange = MockServerWebExchange.from(request);
		// @formatter:off
		return this.converter.convert(exchange)
				.cast(BearerTokenAuthenticationToken.class)
				.block();
		// @formatter:on
	}

}
