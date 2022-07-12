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

import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;

/**
 * Data holder for information required to send an {@code AuthNRequest} over a POST
 * binding from the service provider to the identity provider
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 * (line 2031)
 *
 * @since 5.3
 * @see org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver
 */
public class Saml2PostAuthenticationRequest extends AbstractSaml2AuthenticationRequest {

	Saml2PostAuthenticationRequest(String samlRequest, String relayState, String authenticationRequestUri,
			String relyingPartyRegistrationId, String id) {
		super(samlRequest, relayState, authenticationRequestUri, relyingPartyRegistrationId, id);
	}

	/**
	 * @return {@link Saml2MessageBinding#POST}
	 */
	@Override
	public Saml2MessageBinding getBinding() {
		return Saml2MessageBinding.POST;
	}

	/**
	 * Constructs a {@link Builder} from a {@link RelyingPartyRegistration} object.
	 * @param registration a relying party registration
	 * @return a modifiable builder object
	 * @since 5.7
	 */
	public static Builder withRelyingPartyRegistration(RelyingPartyRegistration registration) {
		String location = registration.getAssertingPartyDetails().getSingleSignOnServiceLocation();
		return new Builder(registration).authenticationRequestUri(location);
	}

	/**
	 * Builder class for a {@link Saml2PostAuthenticationRequest} object.
	 */
	public static final class Builder extends AbstractSaml2AuthenticationRequest.Builder<Builder> {

		private Builder(RelyingPartyRegistration registration) {
			super(registration);
		}

		/**
		 * Constructs an immutable {@link Saml2PostAuthenticationRequest} object.
		 * @return an immutable {@link Saml2PostAuthenticationRequest} object.
		 */
		public Saml2PostAuthenticationRequest build() {
			return new Saml2PostAuthenticationRequest(this.samlRequest, this.relayState, this.authenticationRequestUri,
					this.relyingPartyRegistrationId, this.id);
		}

	}

}
