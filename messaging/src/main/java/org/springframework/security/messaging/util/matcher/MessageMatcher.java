/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.messaging.util.matcher;

import java.util.Collections;
import java.util.Map;

import org.springframework.messaging.Message;

/**
 * API for determining if a {@link Message} should be matched on.
 *
 * @author Rob Winch
 * @since 4.0
 */
public interface MessageMatcher<T> {

	/**
	 * Matches every {@link Message}
	 */
	MessageMatcher<Object> ANY_MESSAGE = new MessageMatcher<>() {

		@Override
		public boolean matches(Message<?> message) {
			return true;
		}

		@Override
		public String toString() {
			return "ANY_MESSAGE";
		}

	};

	/**
	 * Returns true if the {@link Message} matches, else false
	 * @param message the {@link Message} to match on
	 * @return true if the {@link Message} matches, else false
	 */
	boolean matches(Message<? extends T> message);

	/**
	 * Returns a {@link MatchResult} for this {@code MessageMatcher}. The default
	 * implementation returns {@link Collections#emptyMap()} when
	 * {@link MatchResult#getVariables()} is invoked.
	 * @return the {@code MatchResult} from comparing this {@code MessageMatcher} against
	 * the {@code Message}
	 * @since 6.5
	 */
	default MatchResult matcher(Message<? extends T> message) {
		boolean match = matches(message);
		return new MatchResult(match, Collections.emptyMap());
	}

	/**
	 * The result of matching against a {@code Message} contains the status, true or
	 * false, of the match and if present, any variables extracted from the match
	 *
	 * @since 6.5
	 */
	class MatchResult {

		private final boolean match;

		private final Map<String, String> variables;

		MatchResult(boolean match, Map<String, String> variables) {
			this.match = match;
			this.variables = variables;
		}

		/**
		 * Return whether the comparison against the {@code Message} produced a successful
		 * match
		 */
		public boolean isMatch() {
			return this.match;
		}

		/**
		 * Returns the extracted variable values where the key is the variable name and
		 * the value is the variable value
		 * @return a map containing key-value pairs representing extracted variable names
		 * and variable values
		 */
		public Map<String, String> getVariables() {
			return this.variables;
		}

		/**
		 * Creates an instance of {@link MatchResult} that is a match with no variables
		 */
		public static MatchResult match() {
			return new MatchResult(true, Collections.emptyMap());
		}

		/**
		 * Creates an instance of {@link MatchResult} that is a match with the specified
		 * variables
		 */
		public static MatchResult match(Map<String, String> variables) {
			return new MatchResult(true, variables);
		}

		/**
		 * Creates an instance of {@link MatchResult} that is not a match.
		 * @return a {@code MatchResult} with match set to false
		 */
		public static MatchResult notMatch() {
			return new MatchResult(false, Collections.emptyMap());
		}

	}

}
