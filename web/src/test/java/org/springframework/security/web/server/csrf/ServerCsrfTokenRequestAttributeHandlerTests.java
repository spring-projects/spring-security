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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link ServerCsrfTokenRequestAttributeHandler}.
 *
 * @author Steve Riesenberg
 * @since 5.8
 */
public class ServerCsrfTokenRequestAttributeHandlerTests {

	private ServerCsrfTokenRequestAttributeHandler handler;

	private MockServerWebExchange exchange;

	private CsrfToken token;

	@BeforeEach
	public void setUp() {
		this.handler = new ServerCsrfTokenRequestAttributeHandler();
		this.exchange = MockServerWebExchange.builder(MockServerHttpRequest.get("/")).build();
		this.token = new DefaultCsrfToken("headerName", "paramName", "csrfTokenValue");
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
	public void handleWhenValidParametersThenExchangeAttributeSet() {
		Mono<CsrfToken> csrfToken = Mono.just(this.token);
		this.handler.handle(this.exchange, csrfToken);
		Mono<CsrfToken> csrfTokenAttribute = this.exchange.getAttribute(CsrfToken.class.getName());
		assertThat(csrfTokenAttribute).isNotNull();
		assertThat(csrfTokenAttribute).isEqualTo(csrfToken);
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
				.body(this.token.getParameterName() + "=" + this.token.getToken())).build();
		Mono<String> csrfToken = this.handler.resolveCsrfTokenValue(this.exchange, this.token);
		StepVerifier.create(csrfToken).expectNext(this.token.getToken()).verifyComplete();
	}

	@Test
	public void resolveCsrfTokenValueWhenHeaderSetThenReturnsTokenValue() {
		this.exchange = MockServerWebExchange.builder(MockServerHttpRequest.post("/")
				.header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
				.header(this.token.getHeaderName(), this.token.getToken())).build();
		Mono<String> csrfToken = this.handler.resolveCsrfTokenValue(this.exchange, this.token);
		StepVerifier.create(csrfToken).expectNext(this.token.getToken()).verifyComplete();
	}

	@Test
	public void resolveCsrfTokenValueWhenHeaderAndFormDataSetThenFormDataIsPreferred() {
		this.exchange = MockServerWebExchange.builder(MockServerHttpRequest.post("/")
				.header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
				.header(this.token.getHeaderName(), "header")
				.body(this.token.getParameterName() + "=" + this.token.getToken())).build();
		Mono<String> csrfToken = this.handler.resolveCsrfTokenValue(this.exchange, this.token);
		StepVerifier.create(csrfToken).expectNext(this.token.getToken()).verifyComplete();
	}

}
