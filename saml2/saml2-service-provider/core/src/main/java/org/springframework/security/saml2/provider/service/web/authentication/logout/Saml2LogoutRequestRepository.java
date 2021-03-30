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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;

/**
 * Implementations of this interface are responsible for the persistence of
 * {@link Saml2LogoutRequest} between requests.
 *
 * <p>
 * Used by the {@link Saml2LogoutRequestSuccessHandler} for persisting the Logout Request
 * before it initiates the SAML 2.0 SLO flow. As well, used by
 * {@link OpenSamlLogoutResponseHandler} for resolving the Logout Request associated with
 * that Logout Response.
 *
 * @author Josh Cummings
 * @since 5.5
 * @see Saml2LogoutRequest
 * @see HttpSessionLogoutRequestRepository
 */
public interface Saml2LogoutRequestRepository {

	/**
	 * Returns the {@link Saml2LogoutRequest} associated to the provided
	 * {@code HttpServletRequest} or {@code null} if not available.
	 * @param request the {@code HttpServletRequest}
	 * @return the {@link Saml2LogoutRequest} or {@code null} if not available
	 */
	Saml2LogoutRequest loadLogoutRequest(HttpServletRequest request);

	/**
	 * Persists the {@link Saml2LogoutRequest} associating it to the provided
	 * {@code HttpServletRequest} and/or {@code HttpServletResponse}.
	 * @param logoutRequest the {@link Saml2LogoutRequest}
	 * @param request the {@code HttpServletRequest}
	 * @param response the {@code HttpServletResponse}
	 */
	void saveLogoutRequest(Saml2LogoutRequest logoutRequest, HttpServletRequest request, HttpServletResponse response);

	/**
	 * Removes and returns the {@link Saml2LogoutRequest} associated to the provided
	 * {@code HttpServletRequest} and {@code HttpServletResponse} or if not available
	 * returns {@code null}.
	 * @param request the {@code HttpServletRequest}
	 * @param response the {@code HttpServletResponse}
	 * @return the {@link Saml2LogoutRequest} or {@code null} if not available
	 */
	Saml2LogoutRequest removeLogoutRequest(HttpServletRequest request, HttpServletResponse response);

}
