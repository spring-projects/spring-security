/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.saml2.provider.service.registration;

import java.util.Collection;
import java.util.List;
import java.util.function.Consumer;

import org.springframework.security.saml2.core.Saml2X509Credential;

/**
 * An interface representing SAML 2.0 Asserting Party metadata
 *
 * @author Josh Cummings
 * @since 6.4
 */
public interface AssertingPartyMetadata {

	/**
	 * Get the asserting party's <a href=
	 * "https://www.oasis-open.org/committees/download.php/51890/SAML%20MD%20simplified%20overview.pdf#2.9%20EntityDescriptor">EntityID</a>.
	 *
	 * <p>
	 * Equivalent to the value found in the asserting party's &lt;EntityDescriptor
	 * EntityID="..."/&gt;
	 *
	 * <p>
	 * This value may contain a number of placeholders, which need to be resolved before
	 * use. They are {@code baseUrl}, {@code registrationId}, {@code baseScheme},
	 * {@code baseHost}, and {@code basePort}.
	 * @return the asserting party's EntityID
	 */
	String getEntityId();

	/**
	 * Get the WantAuthnRequestsSigned setting, indicating the asserting party's
	 * preference that relying parties should sign the AuthnRequest before sending.
	 * @return the WantAuthnRequestsSigned value
	 */
	boolean getWantAuthnRequestsSigned();

	/**
	 * Get the list of org.opensaml.saml.ext.saml2alg.SigningMethod Algorithms for this
	 * asserting party, in preference order.
	 *
	 * <p>
	 * Equivalent to the values found in &lt;SigningMethod Algorithm="..."/&gt; in the
	 * asserting party's &lt;IDPSSODescriptor&gt;.
	 * @return the list of SigningMethod Algorithms
	 * @since 5.5
	 */
	List<String> getSigningAlgorithms();

	/**
	 * Get all verification {@link Saml2X509Credential}s associated with this asserting
	 * party
	 * @return all verification {@link Saml2X509Credential}s associated with this
	 * asserting party
	 * @since 5.4
	 */
	Collection<Saml2X509Credential> getVerificationX509Credentials();

	/**
	 * Get all encryption {@link Saml2X509Credential}s associated with this asserting
	 * party
	 * @return all encryption {@link Saml2X509Credential}s associated with this asserting
	 * party
	 * @since 5.4
	 */
	Collection<Saml2X509Credential> getEncryptionX509Credentials();

	/**
	 * Get the <a href=
	 * "https://www.oasis-open.org/committees/download.php/51890/SAML%20MD%20simplified%20overview.pdf#2.5%20Endpoint">SingleSignOnService</a>
	 * Location.
	 *
	 * <p>
	 * Equivalent to the value found in &lt;SingleSignOnService Location="..."/&gt; in the
	 * asserting party's &lt;IDPSSODescriptor&gt;.
	 * @return the SingleSignOnService Location
	 */
	String getSingleSignOnServiceLocation();

	/**
	 * Get the <a href=
	 * "https://www.oasis-open.org/committees/download.php/51890/SAML%20MD%20simplified%20overview.pdf#2.5%20Endpoint">SingleSignOnService</a>
	 * Binding.
	 *
	 * <p>
	 * Equivalent to the value found in &lt;SingleSignOnService Binding="..."/&gt; in the
	 * asserting party's &lt;IDPSSODescriptor&gt;.
	 * @return the SingleSignOnService Location
	 */
	Saml2MessageBinding getSingleSignOnServiceBinding();

	/**
	 * Get the <a href=
	 * "https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf#page=7">SingleLogoutService
	 * Location</a>
	 *
	 * <p>
	 * Equivalent to the value found in &lt;SingleLogoutService Location="..."/&gt; in the
	 * asserting party's &lt;IDPSSODescriptor&gt;.
	 * @return the SingleLogoutService Location
	 * @since 5.6
	 */
	String getSingleLogoutServiceLocation();

	/**
	 * Get the <a href=
	 * "https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf#page=7">SingleLogoutService
	 * Response Location</a>
	 *
	 * <p>
	 * Equivalent to the value found in &lt;SingleLogoutService Location="..."/&gt; in the
	 * asserting party's &lt;IDPSSODescriptor&gt;.
	 * @return the SingleLogoutService Response Location
	 * @since 5.6
	 */
	String getSingleLogoutServiceResponseLocation();

	/**
	 * Get the <a href=
	 * "https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf#page=7">SingleLogoutService
	 * Binding</a>
	 *
	 * <p>
	 * Equivalent to the value found in &lt;SingleLogoutService Binding="..."/&gt; in the
	 * asserting party's &lt;IDPSSODescriptor&gt;.
	 * @return the SingleLogoutService Binding
	 * @since 5.6
	 */
	Saml2MessageBinding getSingleLogoutServiceBinding();

	Builder<?> mutate();

	interface Builder<B extends Builder<B>> {

		/**
		 * Set the asserting party's <a href=
		 * "https://www.oasis-open.org/committees/download.php/51890/SAML%20MD%20simplified%20overview.pdf#2.9%20EntityDescriptor">EntityID</a>.
		 * Equivalent to the value found in the asserting party's &lt;EntityDescriptor
		 * EntityID="..."/&gt;
		 * @param entityId the asserting party's EntityID
		 * @return the {@link B} for further configuration
		 */
		B entityId(String entityId);

		/**
		 * Set the WantAuthnRequestsSigned setting, indicating the asserting party's
		 * preference that relying parties should sign the AuthnRequest before sending.
		 * @param wantAuthnRequestsSigned the WantAuthnRequestsSigned setting
		 * @return the {@link B} for further configuration
		 */
		B wantAuthnRequestsSigned(boolean wantAuthnRequestsSigned);

		/**
		 * Apply this {@link Consumer} to the list of SigningMethod Algorithms
		 * @param signingMethodAlgorithmsConsumer a {@link Consumer} of the list of
		 * SigningMethod Algorithms
		 * @return this {@link B} for further configuration
		 * @since 5.5
		 */
		B signingAlgorithms(Consumer<List<String>> signingMethodAlgorithmsConsumer);

		/**
		 * Apply this {@link Consumer} to the list of {@link Saml2X509Credential}s
		 * @param credentialsConsumer a {@link Consumer} of the {@link List} of
		 * {@link Saml2X509Credential}s
		 * @return the {@link RelyingPartyRegistration.Builder} for further configuration
		 * @since 5.4
		 */
		B verificationX509Credentials(Consumer<Collection<Saml2X509Credential>> credentialsConsumer);

		/**
		 * Apply this {@link Consumer} to the list of {@link Saml2X509Credential}s
		 * @param credentialsConsumer a {@link Consumer} of the {@link List} of
		 * {@link Saml2X509Credential}s
		 * @return the {@link RelyingPartyRegistration.Builder} for further configuration
		 * @since 5.4
		 */
		B encryptionX509Credentials(Consumer<Collection<Saml2X509Credential>> credentialsConsumer);

		/**
		 * Set the <a href=
		 * "https://www.oasis-open.org/committees/download.php/51890/SAML%20MD%20simplified%20overview.pdf#2.5%20Endpoint">SingleSignOnService</a>
		 * Location.
		 *
		 * <p>
		 * Equivalent to the value found in &lt;SingleSignOnService Location="..."/&gt; in
		 * the asserting party's &lt;IDPSSODescriptor&gt;.
		 * @param singleSignOnServiceLocation the SingleSignOnService Location
		 * @return the {@link B} for further configuration
		 */
		B singleSignOnServiceLocation(String singleSignOnServiceLocation);

		/**
		 * Set the <a href=
		 * "https://www.oasis-open.org/committees/download.php/51890/SAML%20MD%20simplified%20overview.pdf#2.5%20Endpoint">SingleSignOnService</a>
		 * Binding.
		 *
		 * <p>
		 * Equivalent to the value found in &lt;SingleSignOnService Binding="..."/&gt; in
		 * the asserting party's &lt;IDPSSODescriptor&gt;.
		 * @param singleSignOnServiceBinding the SingleSignOnService Binding
		 * @return the {@link B} for further configuration
		 */
		B singleSignOnServiceBinding(Saml2MessageBinding singleSignOnServiceBinding);

		/**
		 * Set the <a href=
		 * "https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf#page=7">SingleLogoutService
		 * Location</a>
		 *
		 * <p>
		 * Equivalent to the value found in &lt;SingleLogoutService Location="..."/&gt; in
		 * the asserting party's &lt;IDPSSODescriptor&gt;.
		 * @param singleLogoutServiceLocation the SingleLogoutService Location
		 * @return the {@link B} for further configuration
		 * @since 5.6
		 */
		B singleLogoutServiceLocation(String singleLogoutServiceLocation);

		/**
		 * Set the <a href=
		 * "https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf#page=7">SingleLogoutService
		 * Response Location</a>
		 *
		 * <p>
		 * Equivalent to the value found in &lt;SingleLogoutService
		 * ResponseLocation="..."/&gt; in the asserting party's &lt;IDPSSODescriptor&gt;.
		 * @param singleLogoutServiceResponseLocation the SingleLogoutService Response
		 * Location
		 * @return the {@link B} for further configuration
		 * @since 5.6
		 */
		B singleLogoutServiceResponseLocation(String singleLogoutServiceResponseLocation);

		/**
		 * Set the <a href=
		 * "https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf#page=7">SingleLogoutService
		 * Binding</a>
		 *
		 * <p>
		 * Equivalent to the value found in &lt;SingleLogoutService Binding="..."/&gt; in
		 * the asserting party's &lt;IDPSSODescriptor&gt;.
		 * @param singleLogoutServiceBinding the SingleLogoutService Binding
		 * @return the {@link B} for further configuration
		 * @since 5.6
		 */
		B singleLogoutServiceBinding(Saml2MessageBinding singleLogoutServiceBinding);

		/**
		 * Creates an immutable ProviderDetails object representing the configuration for
		 * an Identity Provider, IDP
		 * @return immutable ProviderDetails object
		 */
		AssertingPartyMetadata build();

	}

}
