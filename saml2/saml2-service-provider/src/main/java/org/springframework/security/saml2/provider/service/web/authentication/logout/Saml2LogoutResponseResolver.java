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

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponse;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

/**
 * Creates a signed SAML 2.0 Logout Response based on information from the
 * {@link HttpServletRequest} and current {@link Authentication}.
 *
 * The returned logout response is suitable for sending to the asserting party based on,
 * for example, the location and binding specified in
 * {@link RelyingPartyRegistration#getAssertingPartyDetails()}.
 *
 * @author Josh Cummings
 * @since 5.6
 * @see RelyingPartyRegistration
 */
public interface Saml2LogoutResponseResolver {

	/**
	 * Prepare to create, sign, and serialize a SAML 2.0 Logout Response.
	 * @param request the HTTP request
	 * @param authentication the current user
	 * @return a signed and serialized SAML 2.0 Logout Response
	 */
	Saml2LogoutResponse resolve(HttpServletRequest request, Authentication authentication);

}
