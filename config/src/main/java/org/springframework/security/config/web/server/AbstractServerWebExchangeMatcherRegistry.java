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

package org.springframework.security.config.web.server;

import java.util.List;

import org.springframework.http.HttpMethod;
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;

/**
 * @author Rob Winch
 * @since 5.0
 */
abstract class AbstractServerWebExchangeMatcherRegistry<T> {

	/**
	 * Maps any request.
	 * @return the object that is chained after creating the
	 * {@link ServerWebExchangeMatcher}
	 */
	public T anyExchange() {
		return matcher(ServerWebExchangeMatchers.anyExchange());
	}

	/**
	 * Maps a {@link List} of {@link PathPatternParserServerWebExchangeMatcher} instances.
	 * @param method the {@link HttpMethod} to use for any {@link HttpMethod}.
	 * @return the object that is chained after creating the
	 * {@link ServerWebExchangeMatcher}
	 */
	public T pathMatchers(HttpMethod method) {
		return pathMatchers(method, new String[] { "/**" });
	}

	/**
	 * Maps a {@link List} of {@link PathPatternParserServerWebExchangeMatcher} instances.
	 * @param method the {@link HttpMethod} to use or {@code null} for any
	 * {@link HttpMethod}.
	 * @param antPatterns the ant patterns to create. If {@code null} or empty, then
	 * matches on nothing. {@link PathPatternParserServerWebExchangeMatcher} from
	 * @return the object that is chained after creating the
	 * {@link ServerWebExchangeMatcher}
	 */
	public T pathMatchers(HttpMethod method, String... antPatterns) {
		return matcher(ServerWebExchangeMatchers.pathMatchers(method, antPatterns));
	}

	/**
	 * Maps a {@link List} of {@link PathPatternParserServerWebExchangeMatcher} instances
	 * that do not care which {@link HttpMethod} is used.
	 * @param antPatterns the ant patterns to create
	 * {@link PathPatternParserServerWebExchangeMatcher} from
	 * @return the object that is chained after creating the
	 * {@link ServerWebExchangeMatcher}
	 */
	public T pathMatchers(String... antPatterns) {
		return matcher(ServerWebExchangeMatchers.pathMatchers(antPatterns));
	}

	/**
	 * Associates a list of {@link ServerWebExchangeMatcher} instances
	 * @param matchers the {@link ServerWebExchangeMatcher} instances
	 * @return the object that is chained after creating the
	 * {@link ServerWebExchangeMatcher}
	 */
	public T matchers(ServerWebExchangeMatcher... matchers) {
		return registerMatcher(new OrServerWebExchangeMatcher(matchers));
	}

	/**
	 * Subclasses should implement this method for returning the object that is chained to
	 * the creation of the {@link ServerWebExchangeMatcher} instances.
	 * @param matcher the {@link ServerWebExchangeMatcher} instances that were created
	 * @return the chained Object for the subclass which allows association of something
	 * else to the {@link ServerWebExchangeMatcher}
	 */
	protected abstract T registerMatcher(ServerWebExchangeMatcher matcher);

	/**
	 * Associates a {@link ServerWebExchangeMatcher} instances
	 * @param matcher the {@link ServerWebExchangeMatcher} instance
	 * @return the object that is chained after creating the
	 * {@link ServerWebExchangeMatcher}
	 */
	private T matcher(ServerWebExchangeMatcher matcher) {
		return registerMatcher(matcher);
	}

}
