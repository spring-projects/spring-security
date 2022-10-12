/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.web.server.csrf;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.stubbing.Answer;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.willAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link XorServerCsrfTokenRequestAttributeHandler}.
 *
 * @author Steve Riesenberg
 * @since 5.8
 */
public class XorServerCsrfTokenRequestAttributeHandlerTests {

	private static final byte[] XOR_CSRF_TOKEN_BYTES = new byte[] { 1, 1, 1, 96, 99, 98 };

	private static final String XOR_CSRF_TOKEN_VALUE = Base64.getEncoder().encodeToString(XOR_CSRF_TOKEN_BYTES);

	private XorServerCsrfTokenRequestAttributeHandler handler;

	private MockServerWebExchange exchange;

	private CsrfToken token;

	private SecureRandom secureRandom;

	@BeforeEach
	public void setUp() {
		this.handler = new XorServerCsrfTokenRequestAttributeHandler();
		this.exchange = MockServerWebExchange.builder(MockServerHttpRequest.get("/")).build();
		this.token = new DefaultCsrfToken("headerName", "paramName", "abc");
		this.secureRandom = mock(SecureRandom.class);
	}

	@Test
	public void setSecureRandomWhenNullThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.handler.setSecureRandom(null))
				.withMessage("secureRandom cannot be null");
		// @formatter:on
	}

	@Test
	public void handleWhenExchangeIsNullThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.handler.handle(null, Mono.just(this.token)))
				.withMessage("exchange cannot be null");
		// @formatter:on
	}

	@Test
	public void handleWhenCsrfTokenIsNullThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.handler.handle(this.exchange, null))
				.withMessage("csrfToken cannot be null");
		// @formatter:on
	}

	@Test
	public void handleWhenSecureRandomSetThenUsed() {
		this.handler.setSecureRandom(this.secureRandom);
		this.handler.handle(this.exchange, Mono.just(this.token));
		Mono<CsrfToken> csrfTokenAttribute = this.exchange.getAttribute(CsrfToken.class.getName());
		assertThat(csrfTokenAttribute).isNotNull();
		StepVerifier.create(csrfTokenAttribute).expectNextCount(1).verifyComplete();
		verify(this.secureRandom).nextBytes(anyByteArray());
	}

	@Test
	public void handleWhenValidParametersThenExchangeAttributeSet() {
		willAnswer(fillByteArray()).given(this.secureRandom).nextBytes(anyByteArray());

		this.handler.setSecureRandom(this.secureRandom);
		this.handler.handle(this.exchange, Mono.just(this.token));
		Mono<CsrfToken> csrfTokenAttribute = this.exchange.getAttribute(CsrfToken.class.getName());
		assertThat(csrfTokenAttribute).isNotNull();
		// @formatter:off
		StepVerifier.create(csrfTokenAttribute)
				.assertNext((csrfToken) -> assertThat(csrfToken.getToken()).isEqualTo(XOR_CSRF_TOKEN_VALUE))
				.verifyComplete();
		// @formatter:on
		verify(this.secureRandom).nextBytes(anyByteArray());
	}

	@Test
	public void handleWhenCsrfTokenRequestedTwiceThenCached() {
		this.handler.handle(this.exchange, Mono.just(this.token));
		Mono<CsrfToken> csrfTokenAttribute = this.exchange.getAttribute(CsrfToken.class.getName());
		assertThat(csrfTokenAttribute).isNotNull();
		CsrfToken csrfToken1 = csrfTokenAttribute.block();
		CsrfToken csrfToken2 = csrfTokenAttribute.block();
		assertThat(csrfToken1.getToken()).isNotEqualTo(this.token.getToken());
		assertThat(csrfToken1.getToken()).isEqualTo(csrfToken2.getToken());
	}

	@Test
	public void resolveCsrfTokenValueWhenExchangeIsNullThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.handler.resolveCsrfTokenValue(null, this.token))
				.withMessage("exchange cannot be null");
		// @formatter:on
	}

	@Test
	public void resolveCsrfTokenValueWhenCsrfTokenIsNullThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.handler.resolveCsrfTokenValue(this.exchange, null))
				.withMessage("csrfToken cannot be null");
		// @formatter:on
	}

	@Test
	public void resolveCsrfTokenValueWhenTokenNotSetThenReturnsEmptyMono() {
		Mono<String> csrfToken = this.handler.resolveCsrfTokenValue(this.exchange, this.token);
		StepVerifier.create(csrfToken).verifyComplete();
	}

	@Test
	public void resolveCsrfTokenValueWhenFormDataSetThenReturnsTokenValue() {
		this.exchange = MockServerWebExchange.builder(MockServerHttpRequest.post("/")
				.header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
				.body(this.token.getParameterName() + "=" + XOR_CSRF_TOKEN_VALUE)).build();
		Mono<String> csrfToken = this.handler.resolveCsrfTokenValue(this.exchange, this.token);
		StepVerifier.create(csrfToken).expectNext(this.token.getToken()).verifyComplete();
	}

	@Test
	public void resolveCsrfTokenValueWhenHeaderSetThenReturnsTokenValue() {
		this.exchange = MockServerWebExchange.builder(MockServerHttpRequest.post("/")
				.header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
				.header(this.token.getHeaderName(), XOR_CSRF_TOKEN_VALUE)).build();
		Mono<String> csrfToken = this.handler.resolveCsrfTokenValue(this.exchange, this.token);
		StepVerifier.create(csrfToken).expectNext(this.token.getToken()).verifyComplete();
	}

	@Test
	public void resolveCsrfTokenValueWhenHeaderAndFormDataSetThenFormDataIsPreferred() {
		this.exchange = MockServerWebExchange.builder(MockServerHttpRequest.post("/")
				.header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
				.header(this.token.getHeaderName(), "header")
				.body(this.token.getParameterName() + "=" + XOR_CSRF_TOKEN_VALUE)).build();
		Mono<String> csrfToken = this.handler.resolveCsrfTokenValue(this.exchange, this.token);
		StepVerifier.create(csrfToken).expectNext(this.token.getToken()).verifyComplete();
	}

	private static Answer<Void> fillByteArray() {
		return (invocation) -> {
			byte[] bytes = invocation.getArgument(0);
			Arrays.fill(bytes, (byte) 1);
			return null;
		};
	}

	private static byte[] anyByteArray() {
		return any(byte[].class);
	}

}
