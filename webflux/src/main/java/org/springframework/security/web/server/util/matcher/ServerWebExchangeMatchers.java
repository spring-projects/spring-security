/*
 *
 *  * Copyright 2002-2017 the original author or authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */
package org.springframework.security.web.server.util.matcher;

import org.springframework.http.HttpMethod;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

/**
 * @author Rob Winch
 * @since 5.0
 */
public abstract class ServerWebExchangeMatchers {

	public static ServerWebExchangeMatcher antMatchers(HttpMethod method, String... patterns) {
		List<ServerWebExchangeMatcher> matchers = new ArrayList<>(patterns.length);
		for (String pattern : patterns) {
			matchers.add(new PathMatcherServerWebExchangeMatcher(pattern, method));
		}
		return new OrServerWebExchangeMatcher(matchers);
	}

	public static ServerWebExchangeMatcher antMatchers(String... patterns) {
		return antMatchers(null, patterns);
	}

	public static ServerWebExchangeMatcher matchers(ServerWebExchangeMatcher... matchers) {
		return new OrServerWebExchangeMatcher(matchers);
	}

	public static ServerWebExchangeMatcher anyExchange() {
		return new ServerWebExchangeMatcher() {
			@Override
			public Mono<MatchResult> matches(ServerWebExchange exchange) {
				return ServerWebExchangeMatcher.MatchResult.match();
			}
		};
	}

	private ServerWebExchangeMatchers() {
	}
}
