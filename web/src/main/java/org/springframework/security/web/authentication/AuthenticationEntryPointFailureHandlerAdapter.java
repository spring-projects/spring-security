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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.Assert;

/**
 * Adapts a {@link AuthenticationEntryPoint} into a {@link AuthenticationFailureHandler}.
 * When the failure is an {@link AuthenticationServiceException}, it re-throws, to produce
 * an HTTP 500 error.
 *
 * @author Daniel Garnier-Moiroux
 * @since 5.8
 */
public final class AuthenticationEntryPointFailureHandlerAdapter implements AuthenticationFailureHandler {

	private final AuthenticationEntryPoint authenticationEntryPoint;

	public AuthenticationEntryPointFailureHandlerAdapter(AuthenticationEntryPoint authenticationEntryPoint) {
		Assert.notNull(authenticationEntryPoint, "authenticationEntryPoint cannot be null");
		this.authenticationEntryPoint = authenticationEntryPoint;
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failure) throws IOException, ServletException {
		if (AuthenticationServiceException.class.isAssignableFrom(failure.getClass())) {
			throw failure;
		}
		this.authenticationEntryPoint.commence(request, response, failure);
	}

}
