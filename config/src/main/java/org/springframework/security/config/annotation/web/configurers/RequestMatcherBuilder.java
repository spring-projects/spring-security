/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers;

import java.util.ArrayList;
import java.util.List;

import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * An interface that abstracts how matchers are created
 *
 * @author Josh Cummings
 * @since 6.2
 */
interface RequestMatcherBuilder {

	/**
	 * Create a request matcher for the given pattern.
	 *
	 * <p>
	 * For example, you might do something like the following: <code>
	 *     builder.matcher("/controller/**")
	 * </code>
	 * @param pattern the pattern to use, typically an Ant path
	 * @return a {@link RequestMatcher} that matches on the given {@code pattern}
	 */
	RequestMatcher matcher(String pattern);

	/**
	 * Create a request matcher for the given pattern.
	 *
	 * <p>
	 * For example, you might do something like the following: <code>
	 *     builder.matcher(HttpMethod.GET, "/controller/**")
	 * </code>
	 * @param method the HTTP method to use
	 * @param pattern the pattern to use, typically an Ant path
	 * @return a {@link RequestMatcher} that matches on the given HTTP {@code method} and
	 * {@code pattern}
	 */
	RequestMatcher matcher(HttpMethod method, String pattern);

	/**
	 * Create a request matcher that matches any request
	 * @return a {@link RequestMatcher} that matches any request
	 */
	default RequestMatcher any() {
		return AnyRequestMatcher.INSTANCE;
	}

	/**
	 * Create an array request matchers, one for each of the given patterns.
	 *
	 * <p>
	 * For example, you might do something like the following: <code>
	 *     builder.matcher("/controller-one/**", "/controller-two/**")
	 * </code>
	 * @param patterns the patterns to use, typically Ant paths
	 * @return a list of {@link RequestMatcher} that match on the given {@code pattern}
	 */
	default List<RequestMatcher> matchers(String... patterns) {
		List<RequestMatcher> matchers = new ArrayList<>();
		for (String pattern : patterns) {
			matchers.add(matcher(pattern));
		}
		return matchers;
	}

	/**
	 * Create an array request matchers, one for each of the given patterns.
	 *
	 * <p>
	 * For example, you might do something like the following: <code>
	 *     builder.matcher(HttpMethod.POST, "/controller-one/**", "/controller-two/**")
	 * </code>
	 * @param method the HTTP method to use
	 * @param patterns the patterns to use, typically Ant paths
	 * @return a list of {@link RequestMatcher} that match on the given HTTP
	 * {@code method} and {@code pattern}
	 */
	default List<RequestMatcher> matchers(HttpMethod method, String... patterns) {
		List<RequestMatcher> matchers = new ArrayList<>();
		for (String pattern : patterns) {
			matchers.add(matcher(method, pattern));
		}
		return matchers;
	}

}
