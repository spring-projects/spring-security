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

package org.springframework.security.web.server;

import java.util.Collections;

import org.junit.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.handler.FilteringWebHandler;

import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link ExchangeMatcherRedirectWebFilter}.
 *
 * @author Evgeniy Cheban
 */
public class ExchangeMatcherRedirectWebFilterTests {

	@Test
	public void filterWhenRequestMatchThenRedirectToSpecifiedUrl() {
		ExchangeMatcherRedirectWebFilter filter = new ExchangeMatcherRedirectWebFilter(
				new PathPatternParserServerWebExchangeMatcher("/context"), "/test");
		FilteringWebHandler handler = new FilteringWebHandler((e) -> e.getResponse().setComplete(),
				Collections.singletonList(filter));

		WebTestClient client = WebTestClient.bindToWebHandler(handler).build();
		client.get().uri("/context").exchange().expectStatus().isFound().expectHeader()
				.valueEquals(HttpHeaders.LOCATION, "/test");
	}

	@Test
	public void filterWhenRequestNotMatchThenNextFilter() {
		ExchangeMatcherRedirectWebFilter filter = new ExchangeMatcherRedirectWebFilter(
				new PathPatternParserServerWebExchangeMatcher("/context"), "/test");
		FilteringWebHandler handler = new FilteringWebHandler((e) -> e.getResponse().setComplete(),
				Collections.singletonList(filter));

		WebTestClient client = WebTestClient.bindToWebHandler(handler).build();
		client.get().uri("/test").exchange().expectStatus().isOk();
	}

	@Test
	public void constructWhenExchangeMatcherNull() {
		assertThatIllegalArgumentException().isThrownBy(() -> new ExchangeMatcherRedirectWebFilter(null, "/test"))
				.withMessage("exchangeMatcher cannot be null");
	}

	@Test
	public void constructWhenRedirectUrlNull() {
		assertThatIllegalArgumentException().isThrownBy(
				() -> new ExchangeMatcherRedirectWebFilter(new PathPatternParserServerWebExchangeMatcher("/**"), null))
				.withMessage("redirectUrl cannot be empty");
	}

	@Test
	public void constructWhenRedirectUrlEmpty() {
		assertThatIllegalArgumentException().isThrownBy(
				() -> new ExchangeMatcherRedirectWebFilter(new PathPatternParserServerWebExchangeMatcher("/**"), ""))
				.withMessage("redirectUrl cannot be empty");
	}

	@Test
	public void constructWhenRedirectUrlBlank() {
		assertThatIllegalArgumentException().isThrownBy(
				() -> new ExchangeMatcherRedirectWebFilter(new PathPatternParserServerWebExchangeMatcher("/**"), " "))
				.withMessage("redirectUrl cannot be empty");
	}

}
