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

package org.springframework.security.web.authentication;

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * <p>
 * In the pre-authenticated authentication case (unlike CAS, for example) the user will
 * already have been identified through some external mechanism and a secure context
 * established by the time the security-enforcement filter is invoked.
 * <p>
 * Therefore this class isn't actually responsible for the commencement of authentication,
 * as it is in the case of other providers. It will be called if the user is rejected by
 * the AbstractPreAuthenticatedProcessingFilter, resulting in a null authentication.
 * <p>
 * The <code>commence</code> method will always return an
 * <code>HttpServletResponse.SC_FORBIDDEN</code> (403 error).
 *
 * @author Luke Taylor
 * @author Ruud Senden
 * @since 2.0
 * @see org.springframework.security.web.access.ExceptionTranslationFilter
 */
public class Http403ForbiddenEntryPoint implements AuthenticationEntryPoint {

	private static final Log logger = LogFactory.getLog(Http403ForbiddenEntryPoint.class);

	/**
	 * Always returns a 403 error code to the client.
	 */
	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException arg2)
			throws IOException {
		logger.debug("Pre-authenticated entry point called. Rejecting access");
		response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied");
	}

}
