/*
 * Copyright 2002-2015 the original author or authors.
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
import org.springframework.util.Assert;

/**
 * An {@link AccessDeniedHandler} that delegates to other {@link AccessDeniedHandler}
 * instances based upon the type of {@link AccessDeniedException} passed into
 * {@link #handle(HttpServletRequest, HttpServletResponse, AccessDeniedException)}.
 *
 * @author Rob Winch
 * @since 3.2
 *
 */
public final class DelegatingAccessDeniedHandler implements AccessDeniedHandler {

	private final LinkedHashMap<Class<? extends AccessDeniedException>, AccessDeniedHandler> handlers;

	private final AccessDeniedHandler defaultHandler;

	/**
	 * Creates a new instance
	 * @param handlers a map of the {@link AccessDeniedException} class to the
	 * {@link AccessDeniedHandler} that should be used. Each is considered in the order
	 * they are specified and only the first {@link AccessDeniedHandler} is ued.
	 * @param defaultHandler the default {@link AccessDeniedHandler} that should be used
	 * if none of the handlers matches.
	 */
	public DelegatingAccessDeniedHandler(
			LinkedHashMap<Class<? extends AccessDeniedException>, AccessDeniedHandler> handlers,
			AccessDeniedHandler defaultHandler) {
		Assert.notEmpty(handlers, "handlers cannot be null or empty");
		Assert.notNull(defaultHandler, "defaultHandler cannot be null");
		this.handlers = handlers;
		this.defaultHandler = defaultHandler;
	}

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			AccessDeniedException accessDeniedException) throws IOException, ServletException {
		for (Entry<Class<? extends AccessDeniedException>, AccessDeniedHandler> entry : this.handlers.entrySet()) {
			Class<? extends AccessDeniedException> handlerClass = entry.getKey();
			if (handlerClass.isAssignableFrom(accessDeniedException.getClass())) {
				AccessDeniedHandler handler = entry.getValue();
				handler.handle(request, response, accessDeniedException);
				return;
			}
		}
		this.defaultHandler.handle(request, response, accessDeniedException);
	}

}
