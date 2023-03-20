/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.web.session;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Disables encoding URLs using the {@link HttpServletResponse} to prevent including the
 * session id in URLs which is not considered URL because the session id can be leaked in
 * things like HTTP access logs.
 *
 * @author Rob Winch
 * @since 5.7
 */
public class DisableEncodeUrlFilter extends OncePerRequestFilter {

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		filterChain.doFilter(request, new DisableEncodeUrlResponseWrapper(response));
	}

	/**
	 * Disables URL rewriting for the {@link HttpServletResponse} to prevent including the
	 * session id in URLs which is not considered URL because the session id can be leaked
	 * in things like HTTP access logs.
	 *
	 * @author Rob Winch
	 * @since 5.7
	 */
	private static final class DisableEncodeUrlResponseWrapper extends HttpServletResponseWrapper {

		/**
		 * Constructs a response adaptor wrapping the given response.
		 * @param response the {@link HttpServletResponse} to be wrapped.
		 * @throws IllegalArgumentException if the response is null
		 */
		private DisableEncodeUrlResponseWrapper(HttpServletResponse response) {
			super(response);
		}

		@Override
		public String encodeRedirectURL(String url) {
			return url;
		}

		@Override
		public String encodeURL(String url) {
			return url;
		}

	}

}
