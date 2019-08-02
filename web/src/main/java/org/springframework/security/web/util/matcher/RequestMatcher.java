/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.web.util.matcher;

import java.util.Collections;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

/**
 * Simple strategy to match an <tt>HttpServletRequest</tt>.
 *
 * @author Luke Taylor
 * @author Eddú Meléndez
 * @since 3.0.2
 */
public interface RequestMatcher {

	/**
	 * Decides whether the rule implemented by the strategy matches the supplied request.
	 *
	 * @param request the request to check for a match
	 * @return true if the request matches, false otherwise
	 */
	boolean matches(HttpServletRequest request);

	/**
	 * Returns a MatchResult for this RequestMatcher
	 * The default implementation returns  {@link Collections#emptyMap()}
	 * when {@link MatchResult#getVariables()} is invoked.
	 *
	 * @return the MatchResult from comparing this RequestMatcher against the HttpServletRequest
 	 * @since 5.2
	 */
	default MatchResult matcher(HttpServletRequest request) {
		boolean match = matches(request);
		return new MatchResult(match, Collections.emptyMap());
	}

	/**
	 * The result of matching against an HttpServletRequest
	 * Contains the status, true or false, of the match and
	 * if present, any variables extracted from the match
	 * @since 5.2
	 */
	class MatchResult {
		private final boolean match;
		private final Map<String, String> variables;

		MatchResult(boolean match, Map<String, String> variables) {
			this.match = match;
			this.variables = variables;
		}

		/**
		 * @return true if the comparison against the HttpServletRequest produced a successful match
		 */
		public boolean isMatch() {
			return this.match;
		}

		/**
		 * Returns the extracted variable values where the key is the variable name and the value is the variable value
		 *
		 * @return a map containing key-value pairs representing extracted variable names and variable values
		 */
		public Map<String, String> getVariables() {
			return this.variables;
		}

		/**
		 * Creates an instance of {@link MatchResult} that is a match with no variables
		 *
		 * @return
		 */
		public static MatchResult match() {
			return new MatchResult(true, Collections.emptyMap());
		}

		/**
		 * Creates an instance of {@link MatchResult} that is a match with the specified variables
		 *
		 * @param variables
		 * @return
		 */
		public static MatchResult match(Map<String, String> variables) {
			return new MatchResult(true, variables);
		}

		/**
		 * Creates an instance of {@link MatchResult} that is not a match.
		 *
		 * @return
		 */
		public static MatchResult notMatch() {
			return new MatchResult(false, Collections.emptyMap());
		}
	}

}
