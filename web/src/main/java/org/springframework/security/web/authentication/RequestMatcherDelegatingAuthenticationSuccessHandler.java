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

package org.springframework.security.web.authentication;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationSuccessHandler} that delegates to other
 * {@link AuthenticationSuccessHandler} instances based upon the type of
 * {@link HttpServletRequest} passed into
 * {@link #onAuthenticationSuccess(HttpServletRequest, HttpServletResponse, Authentication)}.
 *
 * @author Max Batischev
 * @since 6.3
 *
 */
public final class RequestMatcherDelegatingAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	private final LinkedHashMap<RequestMatcher, AuthenticationSuccessHandler> handlers;

	private final AuthenticationSuccessHandler defaultHandler;

	/**
	 * Creates a new instance
	 * @param handlers a map of {@link RequestMatcher}s to
	 * {@link AuthenticationSuccessHandler}s that should be used. Each is considered in
	 * the order they are specified and only the first
	 * {@link AuthenticationSuccessHandler} is used.
	 * @param defaultHandler the default {@link AuthenticationSuccessHandler} that should
	 * be used if none of the matchers match.
	 */
	public RequestMatcherDelegatingAuthenticationSuccessHandler(
			LinkedHashMap<RequestMatcher, AuthenticationSuccessHandler> handlers,
			AuthenticationSuccessHandler defaultHandler) {
		Assert.notEmpty(handlers, "handlers cannot be null or empty");
		Assert.notNull(defaultHandler, "defaultHandler cannot be null");
		this.handlers = new LinkedHashMap<>(handlers);
		this.defaultHandler = defaultHandler;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {
		for (Map.Entry<RequestMatcher, AuthenticationSuccessHandler> entry : this.handlers.entrySet()) {
			RequestMatcher matcher = entry.getKey();
			if (matcher.matches(request)) {
				AuthenticationSuccessHandler handler = entry.getValue();
				handler.onAuthenticationSuccess(request, response, authentication);
				return;
			}
		}
		this.defaultHandler.onAuthenticationSuccess(request, response, authentication);
	}

}
