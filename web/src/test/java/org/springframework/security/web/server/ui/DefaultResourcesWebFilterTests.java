/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.server.ui;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.server.WebHandler;
import org.springframework.web.server.handler.DefaultWebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Daniel Garnier-Moiroux
 * @since 6.4
 */
class DefaultResourcesWebFilterTests {

	private final WebHandler notFoundHandler = (exchange) -> {
		exchange.getResponse().setStatusCode(HttpStatus.NOT_FOUND);
		return Mono.empty();
	};

	private final DefaultResourcesWebFilter filter = DefaultResourcesWebFilter.css();

	@Test
	void filterWhenPathMatchesThenRenders() {
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/default-ui.css"));
		WebFilterChain filterChain = new DefaultWebFilterChain(this.notFoundHandler, List.of(this.filter));

		filterChain.filter(exchange).block();

		assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.OK);
		assertThat(exchange.getResponse().getHeaders().getContentType())
			.isEqualTo(new MediaType("text", "css", StandardCharsets.UTF_8));
		assertThat(exchange.getResponse().getBodyAsString().block()).contains("body {");
	}

	@Test
	void filterWhenPathDoesNotMatchThenCallsThrough() {
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/does-not-match"));
		WebFilterChain filterChain = new DefaultWebFilterChain(this.notFoundHandler, List.of(this.filter));

		filterChain.filter(exchange).block();

		assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
	}

	@Test
	void toStringPrintsPathAndResource() {
		assertThat(this.filter.toString()).isEqualTo(
				"DefaultResourcesWebFilter{matcher=PathMatcherServerWebExchangeMatcher{pattern='/default-ui.css', method=GET}, resource='org/springframework/security/default-ui.css'}");
	}

}
