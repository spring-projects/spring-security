/*
 * Copyright 2002-2016 the original author or authors.
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

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.util.Assert;

/**
 * A {@link RequestMatcher} that will negate the {@link RequestMatcher} passed in. For
 * example, if the {@link RequestMatcher} passed in returns true,
 * {@link NegatedRequestMatcher} will return false. If the {@link RequestMatcher} passed
 * in returns false, {@link NegatedRequestMatcher} will return true.
 *
 * @author Rob Winch
 * @since 3.2
 */
public class NegatedRequestMatcher implements RequestMatcher {

	private final RequestMatcher requestMatcher;

	/**
	 * Creates a new instance
	 * @param requestMatcher the {@link RequestMatcher} that will be negated.
	 */
	public NegatedRequestMatcher(RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.requestMatcher = requestMatcher;
	}

	@Override
	public boolean matches(HttpServletRequest request) {
		return !this.requestMatcher.matches(request);
	}

	@Override
	public String toString() {
		return "Not [" + this.requestMatcher + "]";
	}

}
