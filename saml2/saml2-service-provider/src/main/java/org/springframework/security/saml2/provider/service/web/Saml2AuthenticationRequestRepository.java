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

package org.springframework.security.saml2.provider.service.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;

/**
 * A repository for {@link AbstractSaml2AuthenticationRequest}
 *
 * @param <T> the type of SAML 2.0 Authentication Request
 * @author Marcus Da Coregio
 * @since 5.6
 */
public interface Saml2AuthenticationRequestRepository<T extends AbstractSaml2AuthenticationRequest> {

	/**
	 * Loads the {@link AbstractSaml2AuthenticationRequest} from the request
	 * @param request the current request
	 * @return the {@link AbstractSaml2AuthenticationRequest} or {@code null} if it is not
	 * present
	 */
	T loadAuthenticationRequest(HttpServletRequest request);

	/**
	 * Saves the current authentication request using the {@link HttpServletRequest} and
	 * {@link HttpServletResponse}
	 * @param authenticationRequest the {@link AbstractSaml2AuthenticationRequest}
	 * @param request the current request
	 * @param response the current response
	 */
	void saveAuthenticationRequest(T authenticationRequest, HttpServletRequest request, HttpServletResponse response);

	/**
	 * Removes the authentication request using the {@link HttpServletRequest} and
	 * {@link HttpServletResponse}
	 * @param request the current request
	 * @param response the current response
	 * @return the removed {@link AbstractSaml2AuthenticationRequest} or {@code null} if
	 * it is not present
	 */
	T removeAuthenticationRequest(HttpServletRequest request, HttpServletResponse response);

}
