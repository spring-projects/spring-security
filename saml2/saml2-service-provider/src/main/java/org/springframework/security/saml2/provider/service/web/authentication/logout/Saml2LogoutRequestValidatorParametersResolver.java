/*
 * Copyright 2002-2023 the original author or authors.
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
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestValidatorParameters;

/**
 * Resolved a SAML 2.0 Logout Request and associated validation parameters from the given
 * {@link HttpServletRequest} and current {@link Authentication}.
 *
 * The returned logout request is suitable for validating, logging out the logged-in user,
 * and initiating the construction of a {@code LogoutResponse}.
 *
 * @author Josh Cummings
 * @since 6.1
 */
public interface Saml2LogoutRequestValidatorParametersResolver {

	/**
	 * Resolve any SAML 2.0 Logout Request and associated
	 * {@link org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration}
	 * @param request the HTTP request
	 * @param authentication the current user, if any; may be null
	 * @return a SAML 2.0 Logout Request, if any; may be null
	 */
	Saml2LogoutRequestValidatorParameters resolve(HttpServletRequest request, Authentication authentication);

}
