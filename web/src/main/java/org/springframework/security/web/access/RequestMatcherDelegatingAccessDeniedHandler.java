/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.web.access;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map.Entry;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * An {@link AccessDeniedHandler} that delegates to other {@link AccessDeniedHandler}
 * instances based upon the type of {@link HttpServletRequest} passed into
 * {@link #handle(HttpServletRequest, HttpServletResponse, AccessDeniedException)}.
 *
 * @author Josh Cummings
 * @since 5.1
 *
 */
public final class RequestMatcherDelegatingAccessDeniedHandler implements AccessDeniedHandler {

	private final LinkedHashMap<RequestMatcher, AccessDeniedHandler> handlers;

	private final AccessDeniedHandler defaultHandler;

	/**
	 * Creates a new instance
	 * @param handlers a map of {@link RequestMatcher}s to {@link AccessDeniedHandler}s
	 * that should be used. Each is considered in the order they are specified and only
	 * the first {@link AccessDeniedHandler} is used.
	 * @param defaultHandler the default {@link AccessDeniedHandler} that should be used
	 * if none of the matchers match.
	 */
	public RequestMatcherDelegatingAccessDeniedHandler(LinkedHashMap<RequestMatcher, AccessDeniedHandler> handlers,
			AccessDeniedHandler defaultHandler) {
		Assert.notEmpty(handlers, "handlers cannot be null or empty");
		Assert.notNull(defaultHandler, "defaultHandler cannot be null");
		this.handlers = new LinkedHashMap<>(handlers);
		this.defaultHandler = defaultHandler;
	}

	public void handle(HttpServletRequest request, HttpServletResponse response,
			AccessDeniedException accessDeniedException) throws IOException, ServletException {
		for (Entry<RequestMatcher, AccessDeniedHandler> entry : this.handlers.entrySet()) {
			RequestMatcher matcher = entry.getKey();
			if (matcher.matches(request)) {
				AccessDeniedHandler handler = entry.getValue();
				handler.handle(request, response, accessDeniedException);
				return;
			}
		}
		defaultHandler.handle(request, response, accessDeniedException);
	}

}
