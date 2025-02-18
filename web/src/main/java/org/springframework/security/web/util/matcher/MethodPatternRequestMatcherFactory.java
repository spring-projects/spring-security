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

package org.springframework.security.web.util.matcher;

import org.springframework.http.HttpMethod;
import org.springframework.lang.Nullable;

/**
 * A strategy for constructing request matchers that match method-path pairs
 *
 * @author Josh Cummings
 * @since 6.5
 */
public interface MethodPatternRequestMatcherFactory {

	/**
	 * Request a method-pattern request matcher given the following {{@code method} and
	 * {@code pattern}.
	 * This method in this case is treated as a wildcard.
	 *
	 * @param pattern the path pattern to use
	 * @return the {@link RequestMatcher}
	 */
	default RequestMatcher matcher(String pattern) {
		return matcher(null, pattern);
	}

	/**
	 * Request a method-pattern request matcher given the following
	 * {@code method} and {@code pattern}.
	 *
	 * @param method the method to use, may be null
	 * @param pattern the path pattern to use
	 * @return the {@link RequestMatcher}
	 */
	RequestMatcher matcher(@Nullable HttpMethod method, String pattern);

}
