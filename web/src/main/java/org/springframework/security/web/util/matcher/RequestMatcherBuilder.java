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

import java.util.ArrayList;
import java.util.List;

import org.springframework.http.HttpMethod;

/**
 * An interface that creates {@link RequestMatcher} instances in different ways
 *
 * @author Josh Cummings
 * @since 6.5
 */
public interface RequestMatcherBuilder {

	/**
	 * Create an array of {@link RequestMatcher}s that matches this method and each
	 * respective pattern.
	 * <p>
	 * {@code pattern}s should start with a slash
	 * </p>
	 * @param method the HTTP method to match
	 * @param patterns the separate set of patterns to match
	 * @return one {@link RequestMatcher} per pattern
	 */
	default RequestMatcher matcher(HttpMethod method, String... patterns) {
		List<RequestMatcher> requestMatchers = new ArrayList<>();
		for (String pattern : patterns) {
			requestMatchers.add(matcher(method, pattern));
		}
		return new OrRequestMatcher(requestMatchers);
	}

	/**
	 * Create an array of {@link RequestMatcher}s that matches each respective pattern
	 * regardless of the HTTP method
	 * <p>
	 * {@code pattern}s should start with a slash
	 * </p>
	 * @param patterns the separate set of patterns to match
	 * @return one {@link RequestMatcher} per pattern
	 */
	default RequestMatcher matcher(String... patterns) {
		return matcher(null, patterns);
	}

	/**
	 * Create a {@link RequestMatcher}s that matches the given pattern
	 * <p>
	 * {@code pattern} should start with a slash
	 * </p>
	 * @param pattern the pattern to match
	 * @return a {@link RequestMatcher} that matches this pattern
	 */
	default RequestMatcher matcher(String pattern) {
		return matcher(null, pattern);
	}

	/**
	 * Create a {@link RequestMatcher}s that matches any request
	 * @return a {@link RequestMatcher} that matches any request
	 */
	default RequestMatcher anyRequest() {
		return AnyRequestMatcher.INSTANCE;
	}

	RequestMatcher matcher(HttpMethod method, String pattern);

}
