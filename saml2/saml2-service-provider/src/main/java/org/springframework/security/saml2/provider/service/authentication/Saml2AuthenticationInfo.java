/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.saml2.provider.service.authentication;

import java.util.List;

import org.opensaml.saml.saml2.core.SessionIndex;

import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

/**
 * Additional SAML 2.0 authentication information
 *
 * <p>
 * SAML 2.0 Single Logout requires that the {@link Authentication#getPrincipal()
 * authenticated principal} or the {@link Authentication} itself implements this
 * interface.
 *
 * @author Christian Schuster
 */
public interface Saml2AuthenticationInfo {

	/**
	 * Get the {@link RelyingPartyRegistration} identifier
	 * @return the {@link RelyingPartyRegistration} identifier
	 */
	String getRelyingPartyRegistrationId();

	/**
	 * Get the {@link SessionIndex} values of the authenticated principal
	 * @return the {@link SessionIndex} values of the authenticated principal
	 */
	List<String> getSessionIndexes();

	/**
	 * Try to obtain a {@link Saml2AuthenticationInfo} instance from an
	 * {@link Authentication}
	 *
	 * <p>
	 * The result is either the {@link Authentication#getPrincipal() authenticated
	 * principal}, the {@link Authentication} itself, or {@code null}.
	 *
	 * <p>
	 * Returning {@code null} indicates that the given {@link Authentication} does not
	 * represent a SAML 2.0 authentication.
	 * @param authentication the {@link Authentication}
	 * @return the {@link Saml2AuthenticationInfo} or {@code null} if unavailable
	 */
	static Saml2AuthenticationInfo fromAuthentication(Authentication authentication) {
		if (authentication == null) {
			return null;
		}
		Object principal = authentication.getPrincipal();
		if (principal instanceof Saml2AuthenticationInfo) {
			return (Saml2AuthenticationInfo) principal;
		}
		if (authentication instanceof Saml2AuthenticationInfo) {
			return (Saml2AuthenticationInfo) authentication;
		}
		return null;
	}

}
