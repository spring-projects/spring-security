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

package org.springframework.security.web.server.csrf;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import reactor.test.publisher.PublisherProbe;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.server.WebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link CrossOriginProtectionWebFilter}.
 *
 * @author Scott Murphy Heiberg
 */
public class CrossOriginProtectionWebFilterTests {

	private final CrossOriginProtectionWebFilter filter = new CrossOriginProtectionWebFilter();

	private final PublisherProbe<Void> chainResult = PublisherProbe.empty();

	private final WebFilterChain chain = (exchange) -> this.chainResult.mono();

	private static MockServerHttpRequest.BodyBuilder post() {
		return MockServerHttpRequest.post("https://bank.example/transfer");
	}

	private void assertContinued(MockServerWebExchange exchange) {
		StepVerifier.create(this.filter.filter(exchange, this.chain)).verifyComplete();
		this.chainResult.assertWasSubscribed();
		assertThat(exchange.getResponse().getStatusCode()).isNull();
	}

	private void assertForbidden(MockServerWebExchange exchange) {
		StepVerifier.create(this.filter.filter(exchange, this.chain)).verifyComplete();
		this.chainResult.assertWasNotSubscribed();
		assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
	}

	@ParameterizedTest
	@ValueSource(strings = { "same-origin", "none" })
	public void filterWhenSecFetchSiteFromThisOriginThenContinues(String site) {
		assertContinued(MockServerWebExchange.from(post().header("Sec-Fetch-Site", site)));
	}

	@ParameterizedTest
	@ValueSource(strings = { "cross-site", "same-site" })
	public void filterWhenSecFetchSiteFromAnotherOriginThenForbidden(String site) {
		assertForbidden(MockServerWebExchange.from(post().header("Sec-Fetch-Site", site)));
	}

	@Test
	public void filterWhenSecFetchSiteCrossSiteAndOriginMatchesThenForbidden() {
		assertForbidden(MockServerWebExchange
			.from(post().header("Sec-Fetch-Site", "cross-site").header("Origin", "https://bank.example")));
	}

	@Test
	public void filterWhenNoSecFetchSiteAndOriginIsRequestOriginThenContinues() {
		assertContinued(MockServerWebExchange.from(post().header("Origin", "https://bank.example")));
	}

	@ParameterizedTest
	@ValueSource(strings = { "https://evil.example", "http://bank.example", "https://bank.example:8443",
			"https://sub.bank.example", "null" })
	public void filterWhenNoSecFetchSiteAndOriginIsAnotherOriginThenForbidden(String origin) {
		assertForbidden(MockServerWebExchange.from(post().header("Origin", origin)));
	}

	@Test
	public void filterWhenNeitherHeaderThenContinues() {
		assertContinued(MockServerWebExchange.from(post()));
	}

	@ParameterizedTest
	@ValueSource(strings = { "GET", "HEAD", "TRACE", "OPTIONS" })
	public void filterWhenSafeMethodFromAnotherOriginThenContinues(String method) {
		assertContinued(MockServerWebExchange
			.from(MockServerHttpRequest.method(HttpMethod.valueOf(method), "https://bank.example/transfer")
				.header("Sec-Fetch-Site", "cross-site")));
	}

	@Test
	public void filterWhenRequireProtectionMatcherDoesNotMatchThenContinues() {
		this.filter.setRequireProtectionMatcher((exchange) -> ServerWebExchangeMatcher.MatchResult.notMatch());
		assertContinued(MockServerWebExchange.from(post().header("Sec-Fetch-Site", "cross-site")));
	}

	@Test
	public void filterWhenSkipExchangeThenContinues() {
		MockServerWebExchange exchange = MockServerWebExchange.from(post().header("Sec-Fetch-Site", "cross-site"));
		CsrfWebFilter.skipExchange(exchange);
		assertContinued(exchange);
	}

	@Test
	public void filterWhenOriginIsTrustedThenContinues() {
		this.filter.setTrustedOrigins(List.of("https://partner.example"));
		assertContinued(MockServerWebExchange
			.from(post().header("Sec-Fetch-Site", "cross-site").header("Origin", "https://Partner.example")));
	}

	@Test
	public void filterWhenOriginIsNotTrustedThenForbidden() {
		this.filter.setTrustedOrigins(List.of("https://partner.example"));
		assertForbidden(MockServerWebExchange
			.from(post().header("Sec-Fetch-Site", "cross-site").header("Origin", "http://partner.example")));
	}

	@Test
	public void filterWhenRejectedThenAccessDeniedHandlerReceivesCsrfException() {
		this.filter.setAccessDeniedHandler((exchange, denied) -> {
			assertThat(denied).isInstanceOf(CsrfException.class)
				.hasMessage("Cross-origin request rejected: Sec-Fetch-Site is cross-site");
			exchange.getResponse().setStatusCode(HttpStatus.I_AM_A_TEAPOT);
			return Mono.empty();
		});
		MockServerWebExchange exchange = MockServerWebExchange.from(post().header("Sec-Fetch-Site", "cross-site"));
		StepVerifier.create(this.filter.filter(exchange, this.chain)).verifyComplete();
		this.chainResult.assertWasNotSubscribed();
		assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.I_AM_A_TEAPOT);
	}

	@Test
	public void filterThenDoesNotStartSession() {
		MockServerWebExchange exchange = MockServerWebExchange.from(post().header("Sec-Fetch-Site", "same-origin"));
		assertContinued(exchange);
		StepVerifier.create(exchange.getSession().map((session) -> session.isStarted()))
			.expectNext(false)
			.verifyComplete();
	}

	@Test
	public void setTrustedOriginsWhenAllThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setTrustedOrigins(List.of("*")));
	}

	@Test
	public void setTrustedOriginsWhenNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setTrustedOrigins(null));
	}

	@Test
	public void setRequireProtectionMatcherWhenNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setRequireProtectionMatcher(null));
	}

	@Test
	public void setAccessDeniedHandlerWhenNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setAccessDeniedHandler(null));
	}

}
