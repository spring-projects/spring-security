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

package org.springframework.security.web.authentication;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.Assert;

/**
 * Adapts a {@link AuthenticationEntryPoint} into a {@link AuthenticationFailureHandler}
 *
 * @author Sergey Bespalov
 * @since 5.2.0
 */
public class AuthenticationEntryPointFailureHandler implements AuthenticationFailureHandler {

	private boolean rethrowAuthenticationServiceException = true;

	private final AuthenticationEntryPoint authenticationEntryPoint;

	public AuthenticationEntryPointFailureHandler(AuthenticationEntryPoint authenticationEntryPoint) {
		Assert.notNull(authenticationEntryPoint, "authenticationEntryPoint cannot be null");
		this.authenticationEntryPoint = authenticationEntryPoint;
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {
		if (!this.rethrowAuthenticationServiceException) {
			this.authenticationEntryPoint.commence(request, response, exception);
			return;
		}
		if (!AuthenticationServiceException.class.isAssignableFrom(exception.getClass())) {
			this.authenticationEntryPoint.commence(request, response, exception);
			return;
		}
		throw exception;
	}

	/**
	 * Set whether to rethrow {@link AuthenticationServiceException}s (defaults to true)
	 * @param rethrowAuthenticationServiceException whether to rethrow
	 * {@link AuthenticationServiceException}s
	 * @since 5.8
	 */
	public void setRethrowAuthenticationServiceException(boolean rethrowAuthenticationServiceException) {
		this.rethrowAuthenticationServiceException = rethrowAuthenticationServiceException;
	}

}
