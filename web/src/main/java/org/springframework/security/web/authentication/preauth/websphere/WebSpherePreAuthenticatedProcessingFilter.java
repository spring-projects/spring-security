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

package org.springframework.security.web.authentication.preauth.websphere;

import javax.servlet.http.HttpServletRequest;

import org.springframework.core.log.LogMessage;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

/**
 * This AbstractPreAuthenticatedProcessingFilter implementation is based on WebSphere
 * authentication. It will use the WebSphere RunAs user principal name as the
 * pre-authenticated principal.
 *
 * @author Ruud Senden
 * @since 2.0
 */
public class WebSpherePreAuthenticatedProcessingFilter extends AbstractPreAuthenticatedProcessingFilter {

	private final WASUsernameAndGroupsExtractor wasHelper;

	/**
	 * Public constructor which overrides the default AuthenticationDetails class to be
	 * used.
	 */
	public WebSpherePreAuthenticatedProcessingFilter() {
		this(new DefaultWASUsernameAndGroupsExtractor());
	}

	WebSpherePreAuthenticatedProcessingFilter(WASUsernameAndGroupsExtractor wasHelper) {
		this.wasHelper = wasHelper;
		setAuthenticationDetailsSource(new WebSpherePreAuthenticatedWebAuthenticationDetailsSource());
	}

	/**
	 * Return the WebSphere user name.
	 */
	@Override
	protected Object getPreAuthenticatedPrincipal(HttpServletRequest httpRequest) {
		Object principal = this.wasHelper.getCurrentUserName();
		this.logger.debug(LogMessage.format("PreAuthenticated WebSphere principal: %s", principal));
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
