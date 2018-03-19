/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.oauth2.client.web;

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.Map;

/**
 * An implementation of an {@link AuthorizationRequestRepository} that stores
 * {@link OAuth2AuthorizationRequest} in the {@code HttpSession}.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AuthorizationRequestRepository
 * @see OAuth2AuthorizationRequest
 */
public final class HttpSessionOAuth2AuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {
	private static final String DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME =
			HttpSessionOAuth2AuthorizationRequestRepository.class.getName() +  ".AUTHORIZATION_REQUEST";
	private final String sessionAttributeName = DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME;

	@Override
	public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
		Assert.notNull(request, "request cannot be null");
		Assert.hasText(request.getParameter(OAuth2ParameterNames.STATE), "state parameter cannot be empty");
		Map<String, OAuth2AuthorizationRequest> authorizationRequests = this.getAuthorizationRequests(request);
		if (authorizationRequests != null) {
			return authorizationRequests.get(request.getParameter(OAuth2ParameterNames.STATE));
		}
		return null;
	}

	@Override
	public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request,
											HttpServletResponse response) {
		Assert.notNull(request, "request cannot be null");
		Assert.notNull(response, "response cannot be null");
		if (authorizationRequest == null) {
			this.removeAuthorizationRequest(request);
			return;
		}
		Assert.hasText(authorizationRequest.getState(), "authorizationRequest.state cannot be empty");
		Map<String, OAuth2AuthorizationRequest> authorizationRequests = this.getAuthorizationRequests(request, true);
		authorizationRequests.put(authorizationRequest.getState(), authorizationRequest);
	}

	@Override
	public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request) {
		Assert.notNull(request, "request cannot be null");
		OAuth2AuthorizationRequest authorizationRequest = this.loadAuthorizationRequest(request);
		if (authorizationRequest != null) {
			Map<String, OAuth2AuthorizationRequest> authorizationRequests = this.getAuthorizationRequests(request);
			authorizationRequests.remove(authorizationRequest.getState());
		}
		return authorizationRequest;
	}

	private Map<String, OAuth2AuthorizationRequest> getAuthorizationRequests(HttpServletRequest request) {
		return this.getAuthorizationRequests(request, false);
	}

	private Map<String, OAuth2AuthorizationRequest> getAuthorizationRequests(HttpServletRequest request, boolean createSession) {
		Map<String, OAuth2AuthorizationRequest> authorizationRequests = null;
		HttpSession session = request.getSession(createSession);
		if (session != null) {
			authorizationRequests = (Map<String, OAuth2AuthorizationRequest>) session.getAttribute(this.sessionAttributeName);
			if (authorizationRequests == null) {
				authorizationRequests = new HashMap<>();
				session.setAttribute(this.sessionAttributeName, authorizationRequests);
			}
		}
		return authorizationRequests;
	}
}
