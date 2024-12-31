/*
 * Copyright 2002-2024 the original author or authors.
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

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.util.Assert;

/**
 * {@link RequestMatcher} that will return true if all of the passed in
 * {@link RequestMatcher} instances match.
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class AndRequestMatcher implements RequestMatcher {

	private final List<RequestMatcher> requestMatchers;

	/**
	 * Creates a new instance
	 * @param requestMatchers the {@link RequestMatcher} instances to try
	 */
	public AndRequestMatcher(List<RequestMatcher> requestMatchers) {
		Assert.notEmpty(requestMatchers, "requestMatchers must contain a value");
		Assert.noNullElements(requestMatchers, "requestMatchers cannot contain null values");
		this.requestMatchers = requestMatchers;
	}

	/**
	 * Creates a new instance
	 * @param requestMatchers the {@link RequestMatcher} instances to try
	 */
	public AndRequestMatcher(RequestMatcher... requestMatchers) {
		this(Arrays.asList(requestMatchers));
	}

	@Override
	public boolean matches(HttpServletRequest request) {
		for (RequestMatcher matcher : this.requestMatchers) {
			if (!matcher.matches(request)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Returns a {@link MatchResult} for this {@link HttpServletRequest}. In the case of a
	 * match, request variables are a composition of the request variables in underlying
	 * matchers. In the event that two matchers have the same key, the last key is the one
	 * propagated.
	 * @param request the HTTP request
	 * @return a {@link MatchResult} based on the given HTTP request
	 * @since 6.1
	 */
	@Override
	public MatchResult matcher(HttpServletRequest request) {
		Map<String, String> variables = new LinkedHashMap<>();
		for (RequestMatcher matcher : this.requestMatchers) {
			MatchResult result = matcher.matcher(request);
			if (!result.isMatch()) {
				return MatchResult.notMatch();
			}
			variables.putAll(result.getVariables());
		}
		return MatchResult.match(variables);
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		AndRequestMatcher that = (AndRequestMatcher) o;
		return Objects.equals(this.requestMatchers, that.requestMatchers);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.requestMatchers);
	}

	@Override
	public String toString() {
		return "And " + this.requestMatchers;
	}

}
