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

package org.springframework.security.saml2.provider.service.web.authentication.logout;

import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;

import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponse;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

/**
 * Creates a signed SAML 2.0 Logout Response based on information from the
 * {@link HttpServletRequest} and current {@link Authentication}.
 *
 * The returned logout response is suitable for sending to the asserting party based on,
 * for example, the location and binding specified in
 * {@link RelyingPartyRegistration#getAssertingPartyMetadata()}.
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
	@Nullable Saml2LogoutResponse resolve(HttpServletRequest request, @Nullable Authentication authentication);

	/**
	 * Prepare to create, sign, and serialize a SAML 2.0 Error Logout Response.
	 * @param request the HTTP request
	 * @param authentication the current user
	 * @param authenticationException the thrown exception when the logout request was
	 * processed
	 * @return a signed and serialized SAML 2.0 Logout Response, or {@code null} if it
	 * cannot generate a SAML 2.0 Error Logout Response
	 * @since 7.0
	 */
	default @Nullable Saml2LogoutResponse resolve(HttpServletRequest request, @Nullable Authentication authentication,
			Saml2AuthenticationException authenticationException) {
		return null;
	}

}
