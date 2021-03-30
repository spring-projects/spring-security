/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.saml2.provider.service.web.authentication.logout;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.util.Assert;

/**
 * An implementation of an {@link Saml2LogoutRequestRepository} that stores
 * {@link Saml2LogoutRequest} in the {@code HttpSession}.
 *
 * @author Josh Cummings
 * @since 5.5
 * @see Saml2LogoutRequestRepository
 * @see Saml2LogoutRequest
 */
public final class HttpSessionLogoutRequestRepository implements Saml2LogoutRequestRepository {

	private static final String DEFAULT_LOGOUT_REQUEST_ATTR_NAME = HttpSessionLogoutRequestRepository.class.getName()
			+ ".LOGOUT_REQUEST";

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Saml2LogoutRequest loadLogoutRequest(HttpServletRequest request) {
		Assert.notNull(request, "request cannot be null");
		String stateParameter = this.getStateParameter(request);
		if (stateParameter == null) {
			return null;
		}
		Map<String, Saml2LogoutRequest> logoutRequests = this.getLogoutRequests(request);
		return logoutRequests.get(stateParameter);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void saveLogoutRequest(Saml2LogoutRequest logoutRequest, HttpServletRequest request,
			HttpServletResponse response) {
		Assert.notNull(request, "request cannot be null");
		Assert.notNull(response, "response cannot be null");
		if (logoutRequest == null) {
			removeLogoutRequest(request, response);
			return;
		}
		String state = logoutRequest.getRelayState();
		Assert.hasText(state, "logoutRequest.state cannot be empty");
		Map<String, Saml2LogoutRequest> logoutRequests = this.getLogoutRequests(request);
		logoutRequests.put(state, logoutRequest);
		request.getSession().setAttribute(DEFAULT_LOGOUT_REQUEST_ATTR_NAME, logoutRequests);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Saml2LogoutRequest removeLogoutRequest(HttpServletRequest request, HttpServletResponse response) {
		Assert.notNull(request, "request cannot be null");
		Assert.notNull(response, "response cannot be null");
		String stateParameter = getStateParameter(request);
		if (stateParameter == null) {
			return null;
		}
		Map<String, Saml2LogoutRequest> logoutRequests = getLogoutRequests(request);
		Saml2LogoutRequest originalRequest = logoutRequests.remove(stateParameter);
		if (!logoutRequests.isEmpty()) {
			request.getSession().setAttribute(DEFAULT_LOGOUT_REQUEST_ATTR_NAME, logoutRequests);
		}
		else {
			request.getSession().removeAttribute(DEFAULT_LOGOUT_REQUEST_ATTR_NAME);
		}
		return originalRequest;
	}

	private String getStateParameter(HttpServletRequest request) {
		return request.getParameter("RelayState");
	}

	private Map<String, Saml2LogoutRequest> getLogoutRequests(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		Map<String, Saml2LogoutRequest> logoutRequests = (session != null)
				? (Map<String, Saml2LogoutRequest>) session.getAttribute(DEFAULT_LOGOUT_REQUEST_ATTR_NAME) : null;
		if (logoutRequests == null) {
			return new HashMap<>();
		}
		return logoutRequests;
	}

}
