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

package org.springframework.security.web.server.util.matcher;

import java.util.ArrayList;
import java.util.List;

import reactor.core.publisher.Mono;

import org.springframework.http.HttpMethod;
import org.springframework.web.server.ServerWebExchange;

/**
 * Provides factory methods for creating common {@link ServerWebExchangeMatcher}
 *
 * @author Rob Winch
 * @since 5.0
 */
public abstract class ServerWebExchangeMatchers {

	private ServerWebExchangeMatchers() {
	}

	/**
	 * Creates a matcher that matches on the specific method and any of the provided
	 * patterns.
	 * @param method the method to match on. If null, any method will be matched
	 * @param patterns the patterns to match on
	 * @return the matcher to use
	 */
	public static ServerWebExchangeMatcher pathMatchers(HttpMethod method, String... patterns) {
		List<ServerWebExchangeMatcher> matchers = new ArrayList<>(patterns.length);
		for (String pattern : patterns) {
			matchers.add(new PathPatternParserServerWebExchangeMatcher(pattern, method));
		}
		return new OrServerWebExchangeMatcher(matchers);
	}

	/**
	 * Creates a matcher that matches on any of the provided patterns.
	 * @param patterns the patterns to match on
	 * @return the matcher to use
	 */
	public static ServerWebExchangeMatcher pathMatchers(String... patterns) {
		return pathMatchers(null, patterns);
	}

	/**
	 * Creates a matcher that will match on any of the provided matchers
	 * @param matchers the matchers to match on
	 * @return the matcher to use
	 */
	public static ServerWebExchangeMatcher matchers(ServerWebExchangeMatcher... matchers) {
		return new OrServerWebExchangeMatcher(matchers);
	}

	/**
	 * Matches any exchange
	 * @return the matcher to use
	 */
	@SuppressWarnings("Convert2Lambda")
	public static ServerWebExchangeMatcher anyExchange() {
		// we don't use a lambda to ensure a unique equals and hashcode
		// which otherwise can cause problems with adding multiple entries to an ordered
		// LinkedHashMap
		return new ServerWebExchangeMatcher() {

			@Override
			public Mono<MatchResult> matches(ServerWebExchange exchange) {
				return ServerWebExchangeMatcher.MatchResult.match();
			}

		};
	}

}
