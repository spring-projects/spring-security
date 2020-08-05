/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.test.web.reactive.server;

import java.util.Arrays;

import reactor.core.publisher.Mono;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest.BaseBuilder;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebHandler;
import org.springframework.web.server.handler.FilteringWebHandler;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class WebTestHandler {

	private final MockWebHandler webHandler = new MockWebHandler();

	private final WebHandler handler;

	private WebTestHandler(WebFilter... filters) {
		this.handler = new FilteringWebHandler(webHandler, Arrays.asList(filters));
	}

	public WebHandlerResult exchange(BaseBuilder<?> baseBuilder) {
		ServerWebExchange exchange = MockServerWebExchange.from(baseBuilder.build());
		return exchange(exchange);
	}

	public WebHandlerResult exchange(ServerWebExchange exchange) {
		handler.handle(exchange).block();
		return new WebHandlerResult(webHandler.exchange);
	}

	public static class WebHandlerResult {

		private final ServerWebExchange exchange;

		private WebHandlerResult(ServerWebExchange exchange) {
			this.exchange = exchange;
		}

		public ServerWebExchange getExchange() {
			return exchange;
		}

	}

	public static WebTestHandler bindToWebFilters(WebFilter... filters) {
		return new WebTestHandler(filters);
	}

	static class MockWebHandler implements WebHandler {

		private ServerWebExchange exchange;

		@Override
		public Mono<Void> handle(ServerWebExchange exchange) {
			this.exchange = exchange;
			return Mono.empty();
		}

	}

}
