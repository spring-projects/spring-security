/*
 * Copyright 2002-2013 the original author or authors.
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

package org.springframework.security.web.header.writers;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Delegates to the provided {@link HeaderWriter} when
 * {@link RequestMatcher#matches(HttpServletRequest)} returns true.
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class DelegatingRequestMatcherHeaderWriter implements HeaderWriter {

	private final RequestMatcher requestMatcher;

	private final HeaderWriter delegateHeaderWriter;

	/**
	 * Creates a new instance
	 * @param requestMatcher the {@link RequestMatcher} to use. If returns true, the
	 * delegateHeaderWriter will be invoked.
	 * @param delegateHeaderWriter the {@link HeaderWriter} to invoke if the
	 * {@link RequestMatcher} returns true.
	 */
	public DelegatingRequestMatcherHeaderWriter(RequestMatcher requestMatcher, HeaderWriter delegateHeaderWriter) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		Assert.notNull(delegateHeaderWriter, "delegateHeaderWriter cannot be null");
		this.requestMatcher = requestMatcher;
		this.delegateHeaderWriter = delegateHeaderWriter;
	}

	@Override
	public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
		if (this.requestMatcher.matches(request)) {
			this.delegateHeaderWriter.writeHeaders(request, response);
		}
	}

	@Override
	public String toString() {
		return getClass().getName() + " [requestMatcher=" + this.requestMatcher + ", delegateHeaderWriter="
				+ this.delegateHeaderWriter + "]";
	}

}
