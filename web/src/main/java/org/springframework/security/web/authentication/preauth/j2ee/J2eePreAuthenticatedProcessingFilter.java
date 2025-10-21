/*
 * Copyright 2004-present the original author or authors.
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

import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;

import org.springframework.core.log.LogMessage;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

/**
 * This AbstractPreAuthenticatedProcessingFilter implementation is based on the J2EE
 * container-based authentication mechanism. It will use the J2EE user principal name as
 * the pre-authenticated principal.
 *
 * @author Ruud Senden
 * @since 2.0
 */
public class J2eePreAuthenticatedProcessingFilter extends AbstractPreAuthenticatedProcessingFilter {

	/**
	 * Return the J2EE user name.
	 */
	@Override
	protected @Nullable Object getPreAuthenticatedPrincipal(HttpServletRequest httpRequest) {
		Object principal = (httpRequest.getUserPrincipal() != null) ? httpRequest.getUserPrincipal().getName() : null;
		this.logger.debug(LogMessage.format("PreAuthenticated J2EE principal: %s", principal));
		return principal;
	}

	/**
	 * For J2EE container-based authentication there is no generic way to retrieve the
	 * credentials, as such this method returns a fixed dummy value.
	 */
	@Override
	protected Object getPreAuthenticatedCredentials(HttpServletRequest httpRequest) {
		return "N/A";
	}

}
