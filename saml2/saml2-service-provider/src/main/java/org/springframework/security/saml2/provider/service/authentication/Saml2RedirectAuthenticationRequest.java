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

package org.springframework.security.saml2.provider.service.authentication;

import java.io.Serial;

import org.jspecify.annotations.Nullable;

import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.util.Assert;

/**
 * Data holder for information required to send an {@code AuthNRequest} over a REDIRECT
 * binding from the service provider to the identity provider
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 * (line 2031)
 *
 * @since 5.3
 * @see org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver
 */
public final class Saml2RedirectAuthenticationRequest extends AbstractSaml2AuthenticationRequest {

	@Serial
	private static final long serialVersionUID = 6476874109764554798L;

	private final @Nullable String sigAlg;

	private final @Nullable String signature;

	private Saml2RedirectAuthenticationRequest(String samlRequest, @Nullable String sigAlg, @Nullable String signature,
			@Nullable String relayState, String authenticationRequestUri, String relyingPartyRegistrationId,
			@Nullable String id) {
		super(samlRequest, relayState, authenticationRequestUri, relyingPartyRegistrationId, id);
		this.sigAlg = sigAlg;
		this.signature = signature;
	}

	/**
	 * Returns the SigAlg value for {@link Saml2MessageBinding#REDIRECT} requests
	 * @return the SigAlg value
	 */
	public @Nullable String getSigAlg() {
		return this.sigAlg;
	}

	/**
	 * Returns the Signature value for {@link Saml2MessageBinding#REDIRECT} requests
	 * @return the Signature value
	 */
	public @Nullable String getSignature() {
		return this.signature;
	}

	/**
	 * @return {@link Saml2MessageBinding#REDIRECT}
	 */
	@Override
	public Saml2MessageBinding getBinding() {
		return Saml2MessageBinding.REDIRECT;
	}

	/**
	 * Constructs a {@link Saml2PostAuthenticationRequest.Builder} from a
	 * {@link RelyingPartyRegistration} object.
	 * @param registration a relying party registration
	 * @return a modifiable builder object
	 * @since 5.7
	 */
	public static Builder withRelyingPartyRegistration(RelyingPartyRegistration registration) {
		String location = registration.getAssertingPartyMetadata().getSingleSignOnServiceLocation();
		return new Builder(registration).authenticationRequestUri(location);
	}

	/**
	 * Builder class for a {@link Saml2RedirectAuthenticationRequest} object.
	 */
	public static final class Builder extends AbstractSaml2AuthenticationRequest.Builder<Builder> {

		private @Nullable String sigAlg;

		private @Nullable String signature;

		private Builder(RelyingPartyRegistration registration) {
			super(registration);
		}

		/**
		 * Sets the {@code SigAlg} parameter that will accompany this AuthNRequest
		 * @param sigAlg the SigAlg parameter value.
		 * @return this object
		 */
		public Builder sigAlg(@Nullable String sigAlg) {
			this.sigAlg = sigAlg;
			return _this();
		}

		/**
		 * Sets the {@code Signature} parameter that will accompany this AuthNRequest
		 * @param signature the Signature parameter value.
		 * @return this object
		 */
		public Builder signature(@Nullable String signature) {
			this.signature = signature;
			return _this();
		}

		/**
		 * Constructs an immutable {@link Saml2RedirectAuthenticationRequest} object.
		 * @return an immutable {@link Saml2RedirectAuthenticationRequest} object.
		 */
		public Saml2RedirectAuthenticationRequest build() {
			Assert.notNull(this.samlRequest, "samlRequest cannot be null");
			Assert.notNull(this.authenticationRequestUri, "authenticationRequestUri cannot be null");
			Assert.notNull(this.relyingPartyRegistrationId, "relyingPartyRegistrationId cannot be null");
			return new Saml2RedirectAuthenticationRequest(this.samlRequest, this.sigAlg, this.signature,
					this.relayState, this.authenticationRequestUri, this.relyingPartyRegistrationId, this.id);
		}

	}

}
