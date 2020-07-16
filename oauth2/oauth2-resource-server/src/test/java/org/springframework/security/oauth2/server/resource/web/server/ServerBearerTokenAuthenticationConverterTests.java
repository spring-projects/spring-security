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
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

/**
 * @author Rob Winch
 * @since 5.1
 */
public class ServerBearerTokenAuthenticationConverterTests {
	private static final String TEST_TOKEN = "test-token";

	private ServerBearerTokenAuthenticationConverter converter;

	@Before
	public void setup() {
		this.converter = new ServerBearerTokenAuthenticationConverter();
	}

	@Test
	public void resolveWhenValidHeaderIsPresentThenTokenIsResolved() {
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest
				.get("/")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + TEST_TOKEN);

		assertThat(convertToToken(request).getToken()).isEqualTo(TEST_TOKEN);
	}

	// gh-8502
	@Test
	public void resolveWhenHeaderEndsWithPaddingIndicatorThenTokenIsResolved() {
		String token = TEST_TOKEN + "==";
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest
				.get("/")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + token);

		assertThat(convertToToken(request).getToken()).isEqualTo(token);
	}

	// gh-7011
	@Test
	public void resolveWhenValidHeaderIsEmptyStringThenTokenIsResolved() {
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest
				.get("/")
				.header(HttpHeaders.AUTHORIZATION, "Bearer ");

		OAuth2AuthenticationException expected = catchThrowableOfType(() -> convertToToken(request),
				OAuth2AuthenticationException.class);
		BearerTokenError error = (BearerTokenError) expected.getError();
		assertThat(error.getErrorCode()).isEqualTo(BearerTokenErrorCodes.INVALID_TOKEN);
		assertThat(error.getUri()).isEqualTo("https://tools.ietf.org/html/rfc6750#section-3.1");
		assertThat(error.getHttpStatus()).isEqualTo(HttpStatus.UNAUTHORIZED);
	}

	@Test
	public void resolveWhenLowercaseHeaderIsPresentThenTokenIsResolved() {
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest
				.get("/")
				.header(HttpHeaders.AUTHORIZATION, "bearer " + TEST_TOKEN);

		assertThat(convertToToken(request).getToken()).isEqualTo(TEST_TOKEN);
	}

	@Test
	public void resolveWhenNoHeaderIsPresentThenTokenIsNotResolved() {
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest
				.get("/");

		assertThat(convertToToken(request)).isNull();
	}

	@Test
	public void resolveWhenHeaderWithWrongSchemeIsPresentThenTokenIsNotResolved() {
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest
				.get("/")
				.header(HttpHeaders.AUTHORIZATION, "Basic " + Base64.getEncoder().encodeToString("test:test".getBytes()));

		assertThat(convertToToken(request)).isNull();
	}

	@Test
	public void resolveWhenHeaderWithMissingTokenIsPresentThenAuthenticationExceptionIsThrown() {
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest
				.get("/")
				.header(HttpHeaders.AUTHORIZATION, "Bearer ");

		assertThatCode(() -> convertToToken(request))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.hasMessageContaining(("Bearer token is malformed"));
	}

	@Test
	public void resolveWhenHeaderWithInvalidCharactersIsPresentThenAuthenticationExceptionIsThrown() {
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest
				.get("/")
				.header(HttpHeaders.AUTHORIZATION, "Bearer an\"invalid\"token");

		assertThatCode(() ->  convertToToken(request))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.hasMessageContaining(("Bearer token is malformed"));
	}

	@Test
	public void resolveWhenValidHeaderIsPresentTogetherWithQueryParameterThenAuthenticationExceptionIsThrown() {
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest
				.get("/")
				.queryParam("access_token", TEST_TOKEN)
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + TEST_TOKEN);

		assertThatCode(() -> convertToToken(request))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.hasMessageContaining("Found multiple bearer tokens in the request");
	}

	@Test
	public void resolveWhenQueryParameterIsPresentAndSupportedThenTokenIsResolved() {
		this.converter.setAllowUriQueryParameter(true);

		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest
				.get("/")
				.queryParam("access_token", TEST_TOKEN);

		assertThat(convertToToken(request).getToken()).isEqualTo(TEST_TOKEN);
	}

	// gh-7011
	@Test
	public void resolveWhenQueryParameterIsEmptyAndSupportedThenOAuth2AuthenticationException() {
		this.converter.setAllowUriQueryParameter(true);

		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest
				.get("/")
				.queryParam("access_token", "");

		OAuth2AuthenticationException expected = catchThrowableOfType(() -> convertToToken(request),
			OAuth2AuthenticationException.class);
		BearerTokenError error = (BearerTokenError) expected.getError();
		assertThat(error.getErrorCode()).isEqualTo(BearerTokenErrorCodes.INVALID_TOKEN);
		assertThat(error.getUri()).isEqualTo("https://tools.ietf.org/html/rfc6750#section-3.1");
		assertThat(error.getHttpStatus()).isEqualTo(HttpStatus.UNAUTHORIZED);
	}

	@Test
	public void resolveWhenQueryParameterIsPresentAndNotSupportedThenTokenIsNotResolved() {
		MockServerHttpRequest.BaseBuilder<?> request = MockServerHttpRequest
				.get("/")
				.queryParam("access_token", TEST_TOKEN);

		assertThat(convertToToken(request)).isNull();
	}

	private BearerTokenAuthenticationToken convertToToken(MockServerHttpRequest.BaseBuilder<?> request) {
		return convertToToken(request.build());
	}

	private BearerTokenAuthenticationToken convertToToken(MockServerHttpRequest request) {
		MockServerWebExchange exchange = MockServerWebExchange.from(request);
		return this.converter.convert(exchange).cast(BearerTokenAuthenticationToken.class).block();
	}
}
