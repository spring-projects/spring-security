/*
 * Copyright 2019 the original author or authors.
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

package org.springframework.security.rsocket.util.matcher;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import reactor.core.publisher.Mono;

import org.springframework.security.rsocket.api.PayloadExchange;

/**
 * An interface for determining if a {@link PayloadExchangeMatcher} matches.
 *
 * @author Rob Winch
 * @since 5.2
 */
public interface PayloadExchangeMatcher {

	/**
	 * Determines if a request matches or not
	 * @param exchange
	 * @return
	 */
	Mono<MatchResult> matches(PayloadExchange exchange);

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
			return this.match;
		}

		/**
		 * Gets potential variables and their values
		 * @return
		 */
		public Map<String, Object> getVariables() {
			return this.variables;
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
		 * Creates an instance of {@link MatchResult} that is a match with the specified
		 * variables
		 * @param variables
		 * @return
		 */
		public static Mono<MatchResult> match(Map<String, ? extends Object> variables) {
			return Mono.just(new MatchResult(true, variables == null ? null : new HashMap<String, Object>(variables)));
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
