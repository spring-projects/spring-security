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
import jakarta.servlet.http.HttpSession;

import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;

/**
 * A {@link Saml2AuthenticationRequestRepository} implementation that uses
 * {@link HttpSession} to store and retrieve the
 * {@link AbstractSaml2AuthenticationRequest}
 *
 * @author Marcus Da Coregio
 * @since 5.6
 */
public class HttpSessionSaml2AuthenticationRequestRepository
		implements Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> {

	private static final String DEFAULT_SAML2_AUTHN_REQUEST_ATTR_NAME = HttpSessionSaml2AuthenticationRequestRepository.class
			.getName().concat(".SAML2_AUTHN_REQUEST");

	private String saml2AuthnRequestAttributeName = DEFAULT_SAML2_AUTHN_REQUEST_ATTR_NAME;

	@Override
	public AbstractSaml2AuthenticationRequest loadAuthenticationRequest(HttpServletRequest request) {
		HttpSession httpSession = request.getSession(false);
		if (httpSession == null) {
			return null;
		}
		return (AbstractSaml2AuthenticationRequest) httpSession.getAttribute(this.saml2AuthnRequestAttributeName);
	}

	@Override
	public void saveAuthenticationRequest(AbstractSaml2AuthenticationRequest authenticationRequest,
			HttpServletRequest request, HttpServletResponse response) {
		if (authenticationRequest == null) {
			removeAuthenticationRequest(request, response);
			return;
		}
		HttpSession httpSession = request.getSession();
		httpSession.setAttribute(this.saml2AuthnRequestAttributeName, authenticationRequest);
	}

	@Override
	public AbstractSaml2AuthenticationRequest removeAuthenticationRequest(HttpServletRequest request,
			HttpServletResponse response) {
		AbstractSaml2AuthenticationRequest authenticationRequest = loadAuthenticationRequest(request);
		if (authenticationRequest == null) {
			return null;
		}
		HttpSession httpSession = request.getSession();
		httpSession.removeAttribute(this.saml2AuthnRequestAttributeName);
		return authenticationRequest;
	}

}
