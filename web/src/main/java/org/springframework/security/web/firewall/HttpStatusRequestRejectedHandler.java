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
package org.springframework.security.web.firewall;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * A simple implementation of {@link RequestRejectedHandler} that sends an error with configurable status code.
 *
 * @author Leonard Brünings
 * @since 5.4
 */
public class HttpStatusRequestRejectedHandler implements RequestRejectedHandler {
	private static final Log logger = LogFactory.getLog(HttpStatusRequestRejectedHandler.class);

	private final int httpError;

	/**
	 * Constructs an instance which uses {@code 400} as response code.
	 */
	public HttpStatusRequestRejectedHandler() {
		httpError = HttpServletResponse.SC_BAD_REQUEST;
	}

	/**
	 * Constructs an instance which uses a configurable http code as response.
	 * @param httpError http status code to use
	 */
	public HttpStatusRequestRejectedHandler(int httpError) {
		this.httpError = httpError;
	}

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			RequestRejectedException requestRejectedException) throws IOException {
		if (logger.isDebugEnabled()) {
			logger.debug("Rejecting request due to: " + requestRejectedException.getMessage(),
					requestRejectedException);
		}
		response.sendError(httpError);
	}
}
