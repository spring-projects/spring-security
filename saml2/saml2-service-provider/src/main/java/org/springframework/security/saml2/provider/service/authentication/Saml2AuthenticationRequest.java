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

import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.function.Consumer;

import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.util.Assert;

/**
 * Data holder for information required to send an {@code AuthNRequest} from the service
 * provider to the identity provider
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 * (line 2031)
 *
 * @since 5.2
 * @deprecated use {@link Saml2AuthenticationRequestContext}
 */
@Deprecated
public final class Saml2AuthenticationRequest {

	private final String issuer;

	private final List<Saml2X509Credential> credentials;

	private final String destination;

	private final String assertionConsumerServiceUrl;

	private Saml2AuthenticationRequest(String issuer, String destination, String assertionConsumerServiceUrl,
			List<Saml2X509Credential> credentials) {
		Assert.hasText(issuer, "issuer cannot be null");
		Assert.hasText(destination, "destination cannot be null");
		Assert.hasText(assertionConsumerServiceUrl, "spAssertionConsumerServiceUrl cannot be null");
		this.issuer = issuer;
		this.destination = destination;
		this.assertionConsumerServiceUrl = assertionConsumerServiceUrl;
		this.credentials = new LinkedList<>();
		for (Saml2X509Credential c : credentials) {
			if (c.isSigningCredential()) {
				this.credentials.add(c);
			}
		}
	}

	/**
	 * returns the issuer, the local SP entity ID, for this authentication request. This
	 * property should be used to populate the {@code AuthNRequest.Issuer} XML element.
	 * This value typically is a URI, but can be an arbitrary string.
	 * @return issuer
	 */
	public String getIssuer() {
		return this.issuer;
	}

	/**
	 * returns the destination, the WEB Single Sign On URI, for this authentication
	 * request. This property populates the {@code AuthNRequest#Destination} XML
	 * attribute.
	 * @return destination
	 */
	public String getDestination() {
		return this.destination;
	}

	/**
	 * Returns the desired {@code AssertionConsumerServiceUrl} that this SP wishes to
	 * receive the assertion on. The IDP may or may not honor this request. This property
	 * populates the {@code AuthNRequest#AssertionConsumerServiceURL} XML attribute.
	 * @return the AssertionConsumerServiceURL value
	 */
	public String getAssertionConsumerServiceUrl() {
		return this.assertionConsumerServiceUrl;
	}

	/**
	 * Returns a list of credentials that can be used to sign the {@code AuthNRequest}
	 * object
	 * @return signing credentials
	 */
	public List<Saml2X509Credential> getCredentials() {
		return this.credentials;
	}

	/**
	 * A builder for {@link Saml2AuthenticationRequest}. returns a builder object
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * A builder for {@link Saml2AuthenticationRequest}.
	 * @param context a context object to copy values from. returns a builder object
	 */
	public static Builder withAuthenticationRequestContext(Saml2AuthenticationRequestContext context) {
		return new Builder().assertionConsumerServiceUrl(context.getAssertionConsumerServiceUrl())
				.issuer(context.getIssuer()).destination(context.getDestination())
				.credentials(c -> c.addAll(context.getRelyingPartyRegistration().getCredentials()));
	}

	/**
	 * A builder for {@link Saml2AuthenticationRequest}.
	 */
	public static final class Builder {

		private String issuer;

		private List<Saml2X509Credential> credentials = new LinkedList<>();

		private String destination;

		private String assertionConsumerServiceUrl;

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
		 * Modifies the collection of {@link Saml2X509Credential} credentials used in
		 * communication between IDP and SP, specifically signing the authentication
		 * request. For example: <code>
		 *     Saml2X509Credential credential = ...;
		 *     return Saml2AuthenticationRequest.withLocalSpEntityId("id")
		 *             .credentials(c -> c.add(credential))
		 *             ...
		 *             .build();
		 * </code>
		 * @param credentials - a consumer that can modify the collection of credentials
		 * @return this object
		 */
		public Builder credentials(Consumer<Collection<Saml2X509Credential>> credentials) {
			credentials.accept(this.credentials);
			return this;
		}

		/**
		 * Sets the Destination for the authentication request. Typically the
		 * {@code Service Provider EntityID}
		 * @param destination - a required value
		 * @return this {@code Builder}
		 */
		public Builder destination(String destination) {
			this.destination = destination;
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
		 * Creates a {@link Saml2AuthenticationRequest} object.
		 * @return the Saml2AuthenticationRequest object
		 * @throws IllegalArgumentException if a required property is not set
		 */
		public Saml2AuthenticationRequest build() {
			return new Saml2AuthenticationRequest(this.issuer, this.destination, this.assertionConsumerServiceUrl,
					this.credentials);
		}

	}

}
