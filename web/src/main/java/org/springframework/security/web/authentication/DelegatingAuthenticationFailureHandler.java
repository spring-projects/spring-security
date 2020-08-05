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
package org.springframework.security.web.authentication;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationFailureHandler} that delegates to other
 * {@link AuthenticationFailureHandler} instances based upon the type of
 * {@link AuthenticationException} passed into
 * {@link #onAuthenticationFailure(HttpServletRequest, HttpServletResponse, AuthenticationException)}
 * .
 *
 * @author Kazuki Shimizu
 * @since 4.0
 */
public class DelegatingAuthenticationFailureHandler implements AuthenticationFailureHandler {

	private final LinkedHashMap<Class<? extends AuthenticationException>, AuthenticationFailureHandler> handlers;

	private final AuthenticationFailureHandler defaultHandler;

	/**
	 * Creates a new instance
	 * @param handlers a map of the {@link AuthenticationException} class to the
	 * {@link AuthenticationFailureHandler} that should be used. Each is considered in the
	 * order they are specified and only the first {@link AuthenticationFailureHandler} is
	 * ued. This parameter cannot specify null or empty.
	 * @param defaultHandler the default {@link AuthenticationFailureHandler} that should
	 * be used if none of the handlers matches. This parameter cannot specify null.
	 * @throws IllegalArgumentException if invalid argument is specified
	 */
	public DelegatingAuthenticationFailureHandler(
			LinkedHashMap<Class<? extends AuthenticationException>, AuthenticationFailureHandler> handlers,
			AuthenticationFailureHandler defaultHandler) {
		Assert.notEmpty(handlers, "handlers cannot be null or empty");
		Assert.notNull(defaultHandler, "defaultHandler cannot be null");
		this.handlers = handlers;
		this.defaultHandler = defaultHandler;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {
		for (Map.Entry<Class<? extends AuthenticationException>, AuthenticationFailureHandler> entry : handlers
				.entrySet()) {
			Class<? extends AuthenticationException> handlerMappedExceptionClass = entry.getKey();
			if (handlerMappedExceptionClass.isAssignableFrom(exception.getClass())) {
				AuthenticationFailureHandler handler = entry.getValue();
				handler.onAuthenticationFailure(request, response, exception);
				return;
			}
		}
		defaultHandler.onAuthenticationFailure(request, response, exception);
	}

}
