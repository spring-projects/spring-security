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

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Used by {@link org.springframework.security.web.FilterChainProxy} to handle an
 * <code>RequestRejectedException</code>.
 *
 * @author Leonard Brünings
 * @since 5.4
 */
public interface RequestRejectedHandler {
	// ~ Methods
	// ========================================================================================================

	/**
	 * Handles an request rejected failure.
	 *
	 * @param request that resulted in an <code>RequestRejectedException</code>
	 * @param response so that the user agent can be advised of the failure
	 * @param requestRejectedException that caused the invocation
	 *
	 * @throws IOException in the event of an IOException
	 * @throws ServletException in the event of a ServletException
	 */
	void handle(HttpServletRequest request, HttpServletResponse response,
			RequestRejectedException requestRejectedException) throws IOException,
			ServletException;
}
