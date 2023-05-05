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

package org.springframework.security.web.util.matcher;

import java.util.List;

/**
 * A factory class to create {@link RequestMatcher} instances.
 *
 * @author Christian Schuster
 * @since 6.1
 */
public final class RequestMatchers {

	/**
	 * Creates a {@link RequestMatcher} that matches if at least one of the given
	 * {@link RequestMatcher}s matches, if <code>matchers</code> are empty then the
	 * returned matcher never matches.
	 * @param matchers the {@link RequestMatcher}s to use
	 * @return the any-of composed {@link RequestMatcher}
	 * @see OrRequestMatcher
	 */
	public static RequestMatcher anyOf(RequestMatcher... matchers) {
		return (matchers.length > 0) ? new OrRequestMatcher(List.of(matchers)) : (request) -> false;
	}

	/**
	 * Creates a {@link RequestMatcher} that matches if all the given
	 * {@link RequestMatcher}s match, if <code>matchers</code> are empty then the returned
	 * matcher always matches.
	 * @param matchers the {@link RequestMatcher}s to use
	 * @return the all-of composed {@link RequestMatcher}
	 * @see AndRequestMatcher
	 */
	public static RequestMatcher allOf(RequestMatcher... matchers) {
		return (matchers.length > 0) ? new AndRequestMatcher(List.of(matchers)) : (request) -> true;
	}

	/**
	 * Creates a {@link RequestMatcher} that matches if the given {@link RequestMatcher}
	 * does not match.
	 * @param matcher the {@link RequestMatcher} to use
	 * @return the inverted {@link RequestMatcher}
	 */
	public static RequestMatcher not(RequestMatcher matcher) {
		return (request) -> !matcher.matches(request);
	}

	private RequestMatchers() {
	}

}
