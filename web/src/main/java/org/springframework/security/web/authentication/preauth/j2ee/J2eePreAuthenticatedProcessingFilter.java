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
package org.springframework.security.web.authentication.preauth.j2ee;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

/**
 * This AbstractPreAuthenticatedProcessingFilter implementation is based on the J2EE
 * container-based authentication mechanism. It will use the J2EE user principal name as
 * the pre-authenticated principal.
 *
 * @author Ruud Senden
 * @since 2.0
 */
public class J2eePreAuthenticatedProcessingFilter extends
		AbstractPreAuthenticatedProcessingFilter {

	/**
	 * Return the J2EE user name.
	 */
	protected Object getPreAuthenticatedPrincipal(HttpServletRequest httpRequest) {
		Object principal = httpRequest.getUserPrincipal() == null ? null : httpRequest
				.getUserPrincipal().getName();
		if (logger.isDebugEnabled()) {
			logger.debug("PreAuthenticated J2EE principal: " + principal);
		}
		return principal;
	}

	/**
	 * For J2EE container-based authentication there is no generic way to retrieve the
	 * credentials, as such this method returns a fixed dummy value.
	 */
	protected Object getPreAuthenticatedCredentials(HttpServletRequest httpRequest) {
		return "N/A";
	}
}
