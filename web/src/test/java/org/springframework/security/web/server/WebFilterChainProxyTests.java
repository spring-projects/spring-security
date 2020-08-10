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

package org.springframework.security.web.server;

import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher.MatchResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;

/**
 * @author Rob Winch
 * @since 5.0
 */

public class WebFilterChainProxyTests {

	// gh-4668
	@Test
	public void filterWhenNoMatchThenContinuesChainAnd404() {
		List<WebFilter> filters = Arrays.asList(new Http200WebFilter());
		ServerWebExchangeMatcher notMatch = exchange -> MatchResult.notMatch();
		MatcherSecurityWebFilterChain chain = new MatcherSecurityWebFilterChain(notMatch, filters);
		WebFilterChainProxy filter = new WebFilterChainProxy(chain);

		WebTestClient.bindToController(new Object()).webFilter(filter).build().get().exchange().expectStatus()
				.isNotFound();
	}

	static class Http200WebFilter implements WebFilter {

		@Override
		public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
			return Mono.fromRunnable(() -> exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN));
		}

	}

}
