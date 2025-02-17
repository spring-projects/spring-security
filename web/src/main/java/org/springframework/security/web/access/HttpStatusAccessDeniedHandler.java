/*
 * Copyright 2002-2025 the original author or authors.
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

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.util.Assert;

/**
 * An {@link AccessDeniedHandler} that sends an {@link HttpStatus} as a response.
 *
 * @author Sangyoon Jeong
 * @since 6.5
 */
public final class HttpStatusAccessDeniedHandler implements AccessDeniedHandler {

	private static final Log logger = LogFactory.getLog(HttpStatusAccessDeniedHandler.class);

	private final HttpStatus httpStatus;

	/**
	 * Creates a new instance.
	 * @param httpStatus the HttpStatus to set
	 */
	public HttpStatusAccessDeniedHandler(HttpStatus httpStatus) {
		Assert.notNull(httpStatus, "httpStatus cannot be null");
		this.httpStatus = httpStatus;
	}

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			AccessDeniedException accessDeniedException) throws IOException, ServletException {
		logger.debug(LogMessage.format("Access denied with status code %d", this.httpStatus.value()));

		response.sendError(this.httpStatus.value(), "Access Denied");
	}

}
