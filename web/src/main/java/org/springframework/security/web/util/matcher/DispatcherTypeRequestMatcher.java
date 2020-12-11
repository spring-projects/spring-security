/*
 * Copyright 2002-2020 the original author or authors.
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

import javax.servlet.DispatcherType;
import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.lang.Nullable;
import org.springframework.util.StringUtils;

/**
 * Checks the {@link DispatcherType} to decide whether to match a given request.
 * {@code HttpServletRequest}.
 *
 * Can also be configured to match a specific HTTP method.
 *
 * @author Nick McKinney
 * @since 5.5
 */
public class DispatcherTypeRequestMatcher implements RequestMatcher {

	private final DispatcherType dispatcherType;

	@Nullable
	private final HttpMethod httpMethod;

	/**
	 * Creates an instance which matches requests with the provided {@link DispatcherType}
	 * @param dispatcherType the type to match against
	 */
	public DispatcherTypeRequestMatcher(DispatcherType dispatcherType) {
		this(dispatcherType, null);
	}

	/**
	 * Creates an instance which matches requests with the provided {@link DispatcherType}
	 * and {@link HttpMethod}
	 * @param dispatcherType the type to match against
	 * @param httpMethod the HTTP method to match. May be null to match all methods.
	 */
	public DispatcherTypeRequestMatcher(DispatcherType dispatcherType, @Nullable HttpMethod httpMethod) {
		this.dispatcherType = dispatcherType;
		this.httpMethod = httpMethod;
	}

	/**
	 * Performs the match against the request's method and dispatcher type.
	 * @param request the request to check for a match
	 * @return true if the http method and dispatcher type align
	 */
	@Override
	public boolean matches(HttpServletRequest request) {
		if (this.httpMethod != null && StringUtils.hasText(request.getMethod())
				&& this.httpMethod != HttpMethod.resolve(request.getMethod())) {
			return false;
		}
		return this.dispatcherType == request.getDispatcherType();
	}

	@Override
	public String toString() {
		return "DispatcherTypeRequestMatcher{" + "dispatcherType=" + this.dispatcherType + ", httpMethod="
				+ this.httpMethod + '}';
	}

}
