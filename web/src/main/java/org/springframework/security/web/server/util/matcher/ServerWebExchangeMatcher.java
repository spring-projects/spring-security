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

import java.util.Collections;
import java.util.Map;

import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * An interface for determining if a {@link ServerWebExchangeMatcher} matches.
 * @author Rob Winch
 * @since 5.0
 */
public interface ServerWebExchangeMatcher {

	/**
	 * Determines if a request matches or not
	 * @param exchange
	 * @return
	 */
	Mono<MatchResult> matches(ServerWebExchange exchange);

	/**
	 * The result of matching
	 */
	class MatchResult {
		private final boolean match;
		private final Map<String, Object> variables;

		private MatchResult(boolean match, Map<String, Object> variables) {
			this.match = match;
			this.variables = variables;
		}

		public boolean isMatch() {
			return match;
		}

		/**
		 * Gets potential variables and their values
		 * @return
		 */
		public Map<String, Object> getVariables() {
			return variables;
		}

		/**
		 * Creates an instance of {@link MatchResult} that is a match with no variables
		 * @return
		 */
		public static Mono<MatchResult> match() {
			return match(Collections.emptyMap());
		}

		/**
		 *
		 * Creates an instance of {@link MatchResult} that is a match with the specified variables
		 * @param variables
		 * @return
		 */
		public static Mono<MatchResult> match(Map<String, Object> variables) {
			return Mono.just(new MatchResult(true, variables));
		}

		/**
		 * Creates an instance of {@link MatchResult} that is not a match.
		 * @return
		 */
		public static Mono<MatchResult> notMatch() {
			return Mono.just(new MatchResult(false, Collections.emptyMap()));
		}
	}
}
