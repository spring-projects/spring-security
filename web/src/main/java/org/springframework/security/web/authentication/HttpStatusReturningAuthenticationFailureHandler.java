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

package org.springframework.security.web.authentication;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationFailureHandler} that returns an HTTP status code of {@code 401}
 * (Unauthorized) by default.
 *
 * @author Matthias Luppi
 * @since 5.5
 */
public class HttpStatusReturningAuthenticationFailureHandler implements AuthenticationFailureHandler {

	private final HttpStatus httpStatus;

	/**
	 * Constructor which sets the user-defined {@link HttpStatus} that should be returned
	 * when the authentication failed.
	 * @param httpStatus The {@link HttpStatus} to return, must not be {@code null}.
	 */
	public HttpStatusReturningAuthenticationFailureHandler(HttpStatus httpStatus) {
		Assert.notNull(httpStatus, "The provided HttpStatus must not be null.");
		this.httpStatus = httpStatus;
	}

	/**
	 * Constructor which initializes the default {@link HttpStatus#UNAUTHORIZED}.
	 */
	public HttpStatusReturningAuthenticationFailureHandler() {
		this.httpStatus = HttpStatus.UNAUTHORIZED;
	}

	/**
	 * Implementation of
	 * {@link AuthenticationFailureHandler#onAuthenticationFailure(HttpServletRequest, HttpServletResponse, AuthenticationException)}.
	 * Sets the configured status on the {@link HttpServletResponse}.
	 */
	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException e) throws IOException {
		response.setStatus(this.httpStatus.value());
		response.getWriter().flush();
	}

}
