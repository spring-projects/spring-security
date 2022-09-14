/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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
import org.springframework.security.web.WebAttributes;
import org.springframework.util.Assert;

/**
 * Base implementation of {@link AccessDeniedHandler}.
 * <p>
 * This implementation sends a 403 (SC_FORBIDDEN) HTTP error code. In addition, if an
 * {@link #errorPage} is defined, the implementation will perform a request dispatcher
 * "forward" to the specified error page view. Being a "forward", the
 * <code>SecurityContextHolder</code> will remain populated. This is of benefit if the
 * view (or a tag library or macro) wishes to access the
 * <code>SecurityContextHolder</code>. The request scope will also be populated with the
 * exception itself, available from the key {@link WebAttributes#ACCESS_DENIED_403}.
 *
 * @author Ben Alex
 */
public class AccessDeniedHandlerImpl implements AccessDeniedHandler {

	protected static final Log logger = LogFactory.getLog(AccessDeniedHandlerImpl.class);

	private String errorPage;

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			AccessDeniedException accessDeniedException) throws IOException, ServletException {
		if (response.isCommitted()) {
			logger.trace("Did not write to response since already committed");
			return;
		}
		if (this.errorPage == null) {
			logger.debug("Responding with 403 status code");
			response.sendError(HttpStatus.FORBIDDEN.value(), HttpStatus.FORBIDDEN.getReasonPhrase());
			return;
		}
		// Put exception into request scope (perhaps of use to a view)
		request.setAttribute(WebAttributes.ACCESS_DENIED_403, accessDeniedException);
		// Set the 403 status code.
		response.setStatus(HttpStatus.FORBIDDEN.value());
		// forward to error page.
		if (logger.isDebugEnabled()) {
			logger.debug(LogMessage.format("Forwarding to %s with status code 403", this.errorPage));
		}
		request.getRequestDispatcher(this.errorPage).forward(request, response);
	}

	/**
	 * The error page to use. Must begin with a "/" and is interpreted relative to the
	 * current context root.
	 * @param errorPage the dispatcher path to display
	 * @throws IllegalArgumentException if the argument doesn't comply with the above
	 * limitations
	 */
	public void setErrorPage(String errorPage) {
		Assert.isTrue(errorPage == null || errorPage.startsWith("/"), "errorPage must begin with '/'");
		this.errorPage = errorPage;
	}

}
