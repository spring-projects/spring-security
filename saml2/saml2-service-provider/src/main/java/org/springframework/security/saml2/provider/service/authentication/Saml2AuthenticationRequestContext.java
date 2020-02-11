/*
 * Copyright 2002-2020 the original author or authors.
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
import org.springframework.util.Assert;

/**
 * Data holder for information required to create an {@code AuthNRequest}
 * to be sent from the service provider to the identity provider
 * <a href="https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf">
 * Assertions and Protocols for SAML 2 (line 2031)</a>
 *
 * @see Saml2AuthenticationRequestFactory#createPostAuthenticationRequest(Saml2AuthenticationRequestContext)
 * @see Saml2AuthenticationRequestFactory#createRedirectAuthenticationRequest(Saml2AuthenticationRequestContext)
 * @since 5.3
 */
public final class Saml2AuthenticationRequestContext {
	private final RelyingPartyRegistration relyingPartyRegistration;
	private final String issuer;
	private final String assertionConsumerServiceUrl;
	private final String relayState;

	private Saml2AuthenticationRequestContext(
			RelyingPartyRegistration relyingPartyRegistration,
			String issuer,
			String assertionConsumerServiceUrl,
			String relayState) {
		Assert.hasText(issuer, "issuer cannot be null or empty");
		Assert.notNull(relyingPartyRegistration, "relyingPartyRegistration cannot be null");
		Assert.hasText(assertionConsumerServiceUrl, "spAssertionConsumerServiceUrl cannot be null or empty");
		this.issuer = issuer;
		this.relyingPartyRegistration = relyingPartyRegistration;
		this.assertionConsumerServiceUrl = assertionConsumerServiceUrl;
		this.relayState = relayState;
	}

	/**
	 * Returns the {@link RelyingPartyRegistration} configuration for which the AuthNRequest is intended for.
	 * @return the {@link RelyingPartyRegistration} configuration
	 */
	public RelyingPartyRegistration getRelyingPartyRegistration() {
		return this.relyingPartyRegistration;
	}

	/**
	 * Returns the {@code Issuer} value to be used in the {@code AuthNRequest} object.
	 * This property should be used to populate the {@code AuthNRequest.Issuer} XML element.
	 * This value typically is a URI, but can be an arbitrary string.
	 * @return the Issuer value
	 */
	public String getIssuer() {
		return this.issuer;
	}

	/**
	 * Returns the desired {@code AssertionConsumerServiceUrl} that this SP wishes to receive the
	 * assertion on. The IDP may or may not honor this request.
	 * This property populates the {@code AuthNRequest.AssertionConsumerServiceURL} XML attribute.
	 * @return the AssertionConsumerServiceURL value
	 */
	public String getAssertionConsumerServiceUrl() {
		return assertionConsumerServiceUrl;
	}

	/**
	 * Returns the RelayState value, if present in the parameters
	 * @return the RelayState value, or null if not available
	 */
	public String getRelayState() {
		return this.relayState;
	}

	/**
	 * Returns the {@code Destination}, the WEB Single Sign On URI, for this authentication request.
	 * This property can also populate the {@code AuthNRequest.Destination} XML attribute.
	 * @return the Destination value
	 */
	public String getDestination() {
		return this.getRelyingPartyRegistration().getIdpWebSsoUrl();
	}

	/**
	 * A builder for {@link Saml2AuthenticationRequestContext}.
	 * @return a builder object
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * A builder for {@link Saml2AuthenticationRequestContext}.
	 */
	public static class Builder {
		private String issuer;
		private String assertionConsumerServiceUrl;
		private String relayState;
		private RelyingPartyRegistration relyingPartyRegistration;

		private Builder() {
		}

		/**
		 * Sets the issuer for the authentication request.
		 * @param issuer - a required value
		 * @return this {@code Builder}
		 */
		public Builder issuer(String issuer) {
			this.issuer = issuer;
			return this;
		}

		/**
		 * Sets the {@link RelyingPartyRegistration} used to build the authentication request.
		 * @param relyingPartyRegistration - a required value
		 * @return this {@code Builder}
		 */
		public Builder relyingPartyRegistration(RelyingPartyRegistration relyingPartyRegistration) {
			this.relyingPartyRegistration = relyingPartyRegistration;
			return this;
		}

		/**
		 * Sets the {@code assertionConsumerServiceURL} for the authentication request.
		 * Typically the {@code Service Provider EntityID}
		 * @param assertionConsumerServiceUrl - a required value
		 * @return this {@code Builder}
		 */
		public Builder assertionConsumerServiceUrl(String assertionConsumerServiceUrl) {
			this.assertionConsumerServiceUrl = assertionConsumerServiceUrl;
			return this;
		}

		/**
		 * Sets the {@code RelayState} parameter that will accompany this AuthNRequest
		 * @param relayState the relay state value, unencoded. if null or empty, the parameter will be removed from the map.
		 * @return this object
		 */
		public Builder relayState(String relayState) {
			this.relayState = relayState;
			return this;
		}

		/**
		 * Creates a {@link Saml2AuthenticationRequestContext} object.
		 * @return the Saml2AuthenticationRequest object
		 * @throws {@link IllegalArgumentException} if a required property is not set
		 */
		public Saml2AuthenticationRequestContext build() {
			return new Saml2AuthenticationRequestContext(
					this.relyingPartyRegistration,
					this.issuer,
					this.assertionConsumerServiceUrl,
					this.relayState
			);
		}
	}
}
