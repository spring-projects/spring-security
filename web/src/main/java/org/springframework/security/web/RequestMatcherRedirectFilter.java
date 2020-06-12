/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.web;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Filter that redirects requests that match {@link RequestMatcher} to the specified URL.
 *
 * @author Evgeniy Cheban
 * @since 5.6
 */
public final class RequestMatcherRedirectFilter extends OncePerRequestFilter {

	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	private final RequestMatcher requestMatcher;

	private final String redirectUrl;

	/**
	 * Create and initialize an instance of the filter.
	 * @param requestMatcher the request matcher
	 * @param redirectUrl the redirect URL
	 */
	public RequestMatcherRedirectFilter(RequestMatcher requestMatcher, String redirectUrl) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		Assert.hasText(redirectUrl, "redirectUrl cannot be empty");
		this.requestMatcher = requestMatcher;
		this.redirectUrl = redirectUrl;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (this.requestMatcher.matches(request)) {
			this.redirectStrategy.sendRedirect(request, response, this.redirectUrl);
		}
		else {
			filterChain.doFilter(request, response);
		}
	}

}
