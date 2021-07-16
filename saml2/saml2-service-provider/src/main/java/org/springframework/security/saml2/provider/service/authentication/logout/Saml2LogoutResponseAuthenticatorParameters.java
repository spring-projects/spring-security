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

package org.springframework.security.saml2.provider.service.authentication.logout;

import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

/**
 * A holder of the parameters needed to invoke {@link Saml2LogoutResponseAuthenticator}
 *
 * @author Josh Cummings
 * @since 5.6
 */
public class Saml2LogoutResponseAuthenticatorParameters {

	private final Saml2LogoutResponse response;

	private final Saml2LogoutRequest request;

	private final RelyingPartyRegistration registration;

	public Saml2LogoutResponseAuthenticatorParameters(Saml2LogoutResponse response, Saml2LogoutRequest request,
			RelyingPartyRegistration registration) {
		this.response = response;
		this.request = request;
		this.registration = registration;
	}

	/**
	 * The SAML 2.0 Logout Response received from the asserting party
	 * @return the logout response
	 */
	public Saml2LogoutResponse getLogoutResponse() {
		return this.response;
	}

	/**
	 * The SAML 2.0 Logout Request sent by the relying party
	 * @return the logout request
	 */
	public Saml2LogoutRequest getLogoutRequest() {
		return this.request;
	}

	/**
	 * The {@link RelyingPartyRegistration} representing this relying party
	 * @return the relying party
	 */
	public RelyingPartyRegistration getRelyingPartyRegistration() {
		return this.registration;
	}

}
