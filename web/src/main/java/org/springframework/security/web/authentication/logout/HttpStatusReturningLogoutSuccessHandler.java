/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.web.authentication.logout;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * Implementation of the {@link LogoutSuccessHandler}. By default returns an HTTP status
 * code of {@code 200}. This is useful in REST-type scenarios where a redirect upon a
 * successful logout is not desired.
 *
 * @author Gunnar Hillert
 * @since 4.0.2
 */
public class HttpStatusReturningLogoutSuccessHandler implements LogoutSuccessHandler {

	private final HttpStatus httpStatusToReturn;

	/**
	 * Initialize the {@code HttpStatusLogoutSuccessHandler} with a user-defined
	 * {@link HttpStatus}.
	 *
	 * @param httpStatusToReturn Must not be {@code null}.
	 */
	public HttpStatusReturningLogoutSuccessHandler(HttpStatus httpStatusToReturn) {
		Assert.notNull(httpStatusToReturn, "The provided HttpStatus must not be null.");
		this.httpStatusToReturn = httpStatusToReturn;
	}

	/**
	 * Initialize the {@code HttpStatusLogoutSuccessHandler} with the default
	 * {@link HttpStatus#OK}.
	 */
	public HttpStatusReturningLogoutSuccessHandler() {
		this.httpStatusToReturn = HttpStatus.OK;
	}

	/**
	 * Implementation of
	 * {@link LogoutSuccessHandler#onLogoutSuccess(HttpServletRequest, HttpServletResponse, Authentication)}
	 * . Sets the status on the {@link HttpServletResponse}.
	 */
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException {
		response.setStatus(this.httpStatusToReturn.value());
		response.getWriter().flush();
	}

}
