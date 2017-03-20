/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.authentication;

import org.springframework.security.oauth2.core.endpoint.AuthorizationRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * An implementation of an {@link AuthorizationRequestRepository} that stores
 * {@link AuthorizationRequestAttributes} in the {@link HttpSession}.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AuthorizationRequestAttributes
 */
public final class HttpSessionAuthorizationRequestRepository implements AuthorizationRequestRepository {
	private static final String DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME =
			HttpSessionAuthorizationRequestRepository.class.getName() +  ".AUTHORIZATION_REQUEST";
	private String sessionAttributeName = DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME;

	@Override
	public AuthorizationRequestAttributes loadAuthorizationRequest(HttpServletRequest request) {
		AuthorizationRequestAttributes authorizationRequest = null;
		HttpSession session = request.getSession(false);
		if (session != null) {
			authorizationRequest = (AuthorizationRequestAttributes) session.getAttribute(this.sessionAttributeName);
		}
		return authorizationRequest;
	}

	@Override
	public void saveAuthorizationRequest(AuthorizationRequestAttributes authorizationRequest, HttpServletRequest request) {
		if (authorizationRequest == null) {
			this.removeAuthorizationRequest(request);
			return;
		}
		request.getSession().setAttribute(this.sessionAttributeName, authorizationRequest);
	}

	@Override
	public AuthorizationRequestAttributes removeAuthorizationRequest(HttpServletRequest request) {
		AuthorizationRequestAttributes authorizationRequest = this.loadAuthorizationRequest(request);
		if (authorizationRequest != null) {
			request.getSession().removeAttribute(this.sessionAttributeName);
		}
		return authorizationRequest;
	}
}
