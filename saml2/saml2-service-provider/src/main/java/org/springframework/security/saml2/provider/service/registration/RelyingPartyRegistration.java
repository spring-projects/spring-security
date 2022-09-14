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

package org.springframework.security.saml2.provider.service.registration;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.function.Consumer;

import org.opensaml.xmlsec.signature.support.SignatureConstants;

import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 * Represents a configured relying party (aka Service Provider) and asserting party (aka
 * Identity Provider) pair.
 *
 * <p>
 * Each RP/AP pair is uniquely identified using a {@code registrationId}, an arbitrary
 * string.
 *
 * <p>
 * A fully configured registration may look like:
 *
 * <pre>
 *	String registrationId = "simplesamlphp";
 *
 * 	String relyingPartyEntityId = "{baseUrl}/saml2/service-provider-metadata/{registrationId}";
 *	String assertionConsumerServiceLocation = "{baseUrl}/login/saml2/sso/{registrationId}";
 *	Saml2X509Credential relyingPartySigningCredential = ...;
 *
 *	String assertingPartyEntityId = "https://simplesaml-for-spring-saml.apps.pcfone.io/saml2/idp/metadata.php";
 *	String singleSignOnServiceLocation = "https://simplesaml-for-spring-saml.apps.pcfone.io/saml2/idp/SSOService.php";
 * 	Saml2X509Credential assertingPartyVerificationCredential = ...;
 *
 *
 *	RelyingPartyRegistration rp = RelyingPartyRegistration.withRegistrationId(registrationId)
 * 			.entityId(relyingPartyEntityId)
 * 			.assertionConsumerServiceLocation(assertingConsumerServiceLocation)
 * 		 	.signingX509Credentials((c) -&gt; c.add(relyingPartySigningCredential))
 * 			.assertingPartyDetails((details) -&gt; details
 * 				.entityId(assertingPartyEntityId));
 * 				.singleSignOnServiceLocation(singleSignOnServiceLocation))
 * 				.verifyingX509Credentials((c) -&gt; c.add(assertingPartyVerificationCredential))
 * 			.build();
 * </pre>
 *
 * @author Filip Hanik
 * @author Josh Cummings
 * @since 5.2
 */
public final class RelyingPartyRegistration {

	private final String registrationId;

	private final String entityId;

	private final String assertionConsumerServiceLocation;

	private final Saml2MessageBinding assertionConsumerServiceBinding;

	private final String singleLogoutServiceLocation;

	private final String singleLogoutServiceResponseLocation;

	private final Collection<Saml2MessageBinding> singleLogoutServiceBindings;

	private final String nameIdFormat;

	private final AssertingPartyDetails assertingPartyDetails;

	private final Collection<Saml2X509Credential> decryptionX509Credentials;

	private final Collection<Saml2X509Credential> signingX509Credentials;

	private RelyingPartyRegistration(String registrationId, String entityId, String assertionConsumerServiceLocation,
			Saml2MessageBinding assertionConsumerServiceBinding, String singleLogoutServiceLocation,
			String singleLogoutServiceResponseLocation, Collection<Saml2MessageBinding> singleLogoutServiceBindings,
			AssertingPartyDetails assertingPartyDetails, String nameIdFormat,
			Collection<Saml2X509Credential> decryptionX509Credentials,
			Collection<Saml2X509Credential> signingX509Credentials) {
		Assert.hasText(registrationId, "registrationId cannot be empty");
		Assert.hasText(entityId, "entityId cannot be empty");
		Assert.hasText(assertionConsumerServiceLocation, "assertionConsumerServiceLocation cannot be empty");
		Assert.notNull(assertionConsumerServiceBinding, "assertionConsumerServiceBinding cannot be null");
		Assert.isTrue(singleLogoutServiceLocation == null || !CollectionUtils.isEmpty(singleLogoutServiceBindings),
				"singleLogoutServiceBindings cannot be null or empty when singleLogoutServiceLocation is set");
		Assert.notNull(assertingPartyDetails, "assertingPartyDetails cannot be null");
		Assert.notNull(decryptionX509Credentials, "decryptionX509Credentials cannot be null");
		for (Saml2X509Credential c : decryptionX509Credentials) {
			Assert.notNull(c, "decryptionX509Credentials cannot contain null elements");
			Assert.isTrue(c.isDecryptionCredential(),
					"All decryptionX509Credentials must have a usage of DECRYPTION set");
		}
		Assert.notNull(signingX509Credentials, "signingX509Credentials cannot be null");
		for (Saml2X509Credential c : signingX509Credentials) {
			Assert.notNull(c, "signingX509Credentials cannot contain null elements");
			Assert.isTrue(c.isSigningCredential(), "All signingX509Credentials must have a usage of SIGNING set");
		}
		this.registrationId = registrationId;
		this.entityId = entityId;
		this.assertionConsumerServiceLocation = assertionConsumerServiceLocation;
		this.assertionConsumerServiceBinding = assertionConsumerServiceBinding;
		this.singleLogoutServiceLocation = singleLogoutServiceLocation;
		this.singleLogoutServiceResponseLocation = singleLogoutServiceResponseLocation;
		this.singleLogoutServiceBindings = Collections.unmodifiableList(new LinkedList<>(singleLogoutServiceBindings));
		this.nameIdFormat = nameIdFormat;
		this.assertingPartyDetails = assertingPartyDetails;
		this.decryptionX509Credentials = Collections.unmodifiableList(new LinkedList<>(decryptionX509Credentials));
		this.signingX509Credentials = Collections.unmodifiableList(new LinkedList<>(signingX509Credentials));
	}

	/**
	 * Get the unique registration id for this RP/AP pair
	 * @return the unique registration id for this RP/AP pair
	 */
	public String getRegistrationId() {
		return this.registrationId;
	}

	/**
	 * Get the relying party's <a href=
	 * "https://www.oasis-open.org/committees/download.php/51890/SAML%20MD%20simplified%20overview.pdf#2.9%20EntityDescriptor">EntityID</a>.
	 *
	 * <p>
	 * Equivalent to the value found in the relying party's &lt;EntityDescriptor
	 * EntityID="..."/&gt;
	 *
	 * <p>
	 * This value may contain a number of placeholders, which need to be resolved before
	 * use. They are {@code baseUrl}, {@code registrationId}, {@code baseScheme},
	 * {@code baseHost}, and {@code basePort}.
	 * @return the relying party's EntityID
	 * @since 5.4
	 */
	public String getEntityId() {
		return this.entityId;
	}

	/**
	 * Get the AssertionConsumerService Location. Equivalent to the value found in
	 * &lt;AssertionConsumerService Location="..."/&gt; in the relying party's
	 * &lt;SPSSODescriptor&gt;.
	 *
	 * This value may contain a number of placeholders, which need to be resolved before
	 * use. They are {@code baseUrl}, {@code registrationId}, {@code baseScheme},
	 * {@code baseHost}, and {@code basePort}.
	 * @return the AssertionConsumerService Location
	 * @since 5.4
	 */
	public String getAssertionConsumerServiceLocation() {
		return this.assertionConsumerServiceLocation;
	}

	/**
	 * Get the AssertionConsumerService Binding. Equivalent to the value found in
	 * &lt;AssertionConsumerService Binding="..."/&gt; in the relying party's
	 * &lt;SPSSODescriptor&gt;.
	 * @return the AssertionConsumerService Binding
	 * @since 5.4
	 */
	public Saml2MessageBinding getAssertionConsumerServiceBinding() {
		return this.assertionConsumerServiceBinding;
	}

	/**
	 * Get the <a href=
	 * "https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf#page=7">SingleLogoutService
	 * Binding</a>
	 *
	 *
	 * <p>
	 * Equivalent to the value found in &lt;SingleLogoutService Binding="..."/&gt; in the
	 * relying party's &lt;SPSSODescriptor&gt;.
	 * @return the SingleLogoutService Binding
	 * @since 5.6
	 */
	public Saml2MessageBinding getSingleLogoutServiceBinding() {
		Assert.state(this.singleLogoutServiceBindings.size() == 1, "Method does not support multiple bindings.");
		return this.singleLogoutServiceBindings.iterator().next();
	}

	/**
	 * Get the <a href=
	 * "https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf#page=7">SingleLogoutService
	 * Binding</a>
	 * <p>
	 * Equivalent to the value found in &lt;SingleLogoutService Binding="..."/&gt; in the
	 * relying party's &lt;SPSSODescriptor&gt;.
	 * @return the SingleLogoutService Binding
	 * @since 5.8
	 */
	public Collection<Saml2MessageBinding> getSingleLogoutServiceBindings() {
		return this.singleLogoutServiceBindings;
	}

	/**
	 * Get the <a href=
	 * "https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf#page=7">SingleLogoutService
	 * Location</a>
	 *
	 * <p>
	 * Equivalent to the value found in &lt;SingleLogoutService Location="..."/&gt; in the
	 * relying party's &lt;SPSSODescriptor&gt;.
	 * @return the SingleLogoutService Location
	 * @since 5.6
	 */
	public String getSingleLogoutServiceLocation() {
		return this.singleLogoutServiceLocation;
	}

	/**
	 * Get the <a href=
	 * "https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf#page=7">SingleLogoutService
	 * Response Location</a>
	 *
	 * <p>
	 * Equivalent to the value found in &lt;SingleLogoutService
	 * ResponseLocation="..."/&gt; in the relying party's &lt;SPSSODescriptor&gt;.
	 * @return the SingleLogoutService Response Location
	 * @since 5.6
	 */
	public String getSingleLogoutServiceResponseLocation() {
		return this.singleLogoutServiceResponseLocation;
	}

	/**
	 * Get the NameID format.
	 * @return the NameID format
	 * @since 5.7
	 */
	public String getNameIdFormat() {
		return this.nameIdFormat;
	}

	/**
	 * Get the {@link Collection} of decryption {@link Saml2X509Credential}s associated
	 * with this relying party
	 * @return the {@link Collection} of decryption {@link Saml2X509Credential}s
	 * associated with this relying party
	 * @since 5.4
	 */
	public Collection<Saml2X509Credential> getDecryptionX509Credentials() {
		return this.decryptionX509Credentials;
	}

	/**
	 * Get the {@link Collection} of signing {@link Saml2X509Credential}s associated with
	 * this relying party
	 * @return the {@link Collection} of signing {@link Saml2X509Credential}s associated
	 * with this relying party
	 * @since 5.4
	 */
	public Collection<Saml2X509Credential> getSigningX509Credentials() {
		return this.signingX509Credentials;
	}

	/**
	 * Get the configuration details for the Asserting Party
	 * @return the {@link AssertingPartyDetails}
	 * @since 5.4
	 */
	public AssertingPartyDetails getAssertingPartyDetails() {
		return this.assertingPartyDetails;
	}

	/**
	 * Creates a {@code RelyingPartyRegistration} {@link Builder} with a known
	 * {@code registrationId}
	 * @param registrationId a string identifier for the {@code RelyingPartyRegistration}
	 * @return {@code Builder} to create a {@code RelyingPartyRegistration} object
	 */
	public static Builder withRegistrationId(String registrationId) {
		Assert.hasText(registrationId, "registrationId cannot be empty");
		return new Builder(registrationId);
	}

	public static Builder withAssertingPartyDetails(AssertingPartyDetails assertingPartyDetails) {
		Assert.notNull(assertingPartyDetails, "assertingPartyDetails cannot be null");
		return withRegistrationId(assertingPartyDetails.getEntityId()).assertingPartyDetails((party) -> party
				.entityId(assertingPartyDetails.getEntityId())
				.wantAuthnRequestsSigned(assertingPartyDetails.getWantAuthnRequestsSigned())
				.signingAlgorithms((algorithms) -> algorithms.addAll(assertingPartyDetails.getSigningAlgorithms()))
				.verificationX509Credentials((c) -> c.addAll(assertingPartyDetails.getVerificationX509Credentials()))
				.encryptionX509Credentials((c) -> c.addAll(assertingPartyDetails.getEncryptionX509Credentials()))
				.singleSignOnServiceLocation(assertingPartyDetails.getSingleSignOnServiceLocation())
				.singleSignOnServiceBinding(assertingPartyDetails.getSingleSignOnServiceBinding())
				.singleLogoutServiceLocation(assertingPartyDetails.getSingleLogoutServiceLocation())
				.singleLogoutServiceResponseLocation(assertingPartyDetails.getSingleLogoutServiceResponseLocation())
				.singleLogoutServiceBinding(assertingPartyDetails.getSingleLogoutServiceBinding()));
	}

	/**
	 * Creates a {@code RelyingPartyRegistration} {@link Builder} based on an existing
	 * object
	 * @param registration the {@code RelyingPartyRegistration}
	 * @return {@code Builder} to create a {@code RelyingPartyRegistration} object
	 */
	public static Builder withRelyingPartyRegistration(RelyingPartyRegistration registration) {
		Assert.notNull(registration, "registration cannot be null");
		return withRegistrationId(registration.getRegistrationId()).entityId(registration.getEntityId())
				.signingX509Credentials((c) -> c.addAll(registration.getSigningX509Credentials()))
				.decryptionX509Credentials((c) -> c.addAll(registration.getDecryptionX509Credentials()))
				.assertionConsumerServiceLocation(registration.getAssertionConsumerServiceLocation())
				.assertionConsumerServiceBinding(registration.getAssertionConsumerServiceBinding())
				.singleLogoutServiceLocation(registration.getSingleLogoutServiceLocation())
				.singleLogoutServiceResponseLocation(registration.getSingleLogoutServiceResponseLocation())
				.singleLogoutServiceBindings((c) -> c.addAll(registration.getSingleLogoutServiceBindings()))
				.nameIdFormat(registration.getNameIdFormat())
				.assertingPartyDetails((assertingParty) -> assertingParty
						.entityId(registration.getAssertingPartyDetails().getEntityId())
						.wantAuthnRequestsSigned(registration.getAssertingPartyDetails().getWantAuthnRequestsSigned())
						.signingAlgorithms((algorithms) -> algorithms
								.addAll(registration.getAssertingPartyDetails().getSigningAlgorithms()))
						.verificationX509Credentials((c) -> c
								.addAll(registration.getAssertingPartyDetails().getVerificationX509Credentials()))
						.encryptionX509Credentials(
								(c) -> c.addAll(registration.getAssertingPartyDetails().getEncryptionX509Credentials()))
						.singleSignOnServiceLocation(
								registration.getAssertingPartyDetails().getSingleSignOnServiceLocation())
						.singleSignOnServiceBinding(
								registration.getAssertingPartyDetails().getSingleSignOnServiceBinding())
						.singleLogoutServiceLocation(
								registration.getAssertingPartyDetails().getSingleLogoutServiceLocation())
						.singleLogoutServiceResponseLocation(
								registration.getAssertingPartyDetails().getSingleLogoutServiceResponseLocation())
						.singleLogoutServiceBinding(
								registration.getAssertingPartyDetails().getSingleLogoutServiceBinding()));
	}

	/**
	 * The configuration metadata of the Asserting party
	 *
	 * @since 5.4
	 */
	public static class AssertingPartyDetails {

		private final String entityId;

		private final boolean wantAuthnRequestsSigned;

		private List<String> signingAlgorithms;

		private final Collection<Saml2X509Credential> verificationX509Credentials;

		private final Collection<Saml2X509Credential> encryptionX509Credentials;

		private final String singleSignOnServiceLocation;

		private final Saml2MessageBinding singleSignOnServiceBinding;

		private final String singleLogoutServiceLocation;

		private final String singleLogoutServiceResponseLocation;

		private final Saml2MessageBinding singleLogoutServiceBinding;

		AssertingPartyDetails(String entityId, boolean wantAuthnRequestsSigned, List<String> signingAlgorithms,
				Collection<Saml2X509Credential> verificationX509Credentials,
				Collection<Saml2X509Credential> encryptionX509Credentials, String singleSignOnServiceLocation,
				Saml2MessageBinding singleSignOnServiceBinding, String singleLogoutServiceLocation,
				String singleLogoutServiceResponseLocation, Saml2MessageBinding singleLogoutServiceBinding) {
			Assert.hasText(entityId, "entityId cannot be null or empty");
			Assert.notEmpty(signingAlgorithms, "signingAlgorithms cannot be empty");
			Assert.notNull(verificationX509Credentials, "verificationX509Credentials cannot be null");
			for (Saml2X509Credential credential : verificationX509Credentials) {
				Assert.notNull(credential, "verificationX509Credentials cannot have null values");
				Assert.isTrue(credential.isVerificationCredential(),
						"All verificationX509Credentials must have a usage of VERIFICATION set");
			}
			Assert.notNull(encryptionX509Credentials, "encryptionX509Credentials cannot be null");
			for (Saml2X509Credential credential : encryptionX509Credentials) {
				Assert.notNull(credential, "encryptionX509Credentials cannot have null values");
				Assert.isTrue(credential.isEncryptionCredential(),
						"All encryptionX509Credentials must have a usage of ENCRYPTION set");
			}
			Assert.notNull(singleSignOnServiceLocation, "singleSignOnServiceLocation cannot be null");
			Assert.notNull(singleSignOnServiceBinding, "singleSignOnServiceBinding cannot be null");
			this.entityId = entityId;
			this.wantAuthnRequestsSigned = wantAuthnRequestsSigned;
			this.signingAlgorithms = signingAlgorithms;
			this.verificationX509Credentials = verificationX509Credentials;
			this.encryptionX509Credentials = encryptionX509Credentials;
			this.singleSignOnServiceLocation = singleSignOnServiceLocation;
			this.singleSignOnServiceBinding = singleSignOnServiceBinding;
			this.singleLogoutServiceLocation = singleLogoutServiceLocation;
			this.singleLogoutServiceResponseLocation = singleLogoutServiceResponseLocation;
			this.singleLogoutServiceBinding = singleLogoutServiceBinding;
		}

		/**
		 * Get the asserting party's <a href=
		 * "https://www.oasis-open.org/committees/download.php/51890/SAML%20MD%20simplified%20overview.pdf#2.9%20EntityDescriptor">EntityID</a>.
		 *
		 * <p>
		 * Equivalent to the value found in the asserting party's &lt;EntityDescriptor
		 * EntityID="..."/&gt;
		 *
		 * <p>
		 * This value may contain a number of placeholders, which need to be resolved
		 * before use. They are {@code baseUrl}, {@code registrationId},
		 * {@code baseScheme}, {@code baseHost}, and {@code basePort}.
		 * @return the asserting party's EntityID
		 */
		public String getEntityId() {
			return this.entityId;
		}

		/**
		 * Get the WantAuthnRequestsSigned setting, indicating the asserting party's
		 * preference that relying parties should sign the AuthnRequest before sending.
		 * @return the WantAuthnRequestsSigned value
		 */
		public boolean getWantAuthnRequestsSigned() {
			return this.wantAuthnRequestsSigned;
		}

		/**
		 * Get the list of org.opensaml.saml.ext.saml2alg.SigningMethod Algorithms for
		 * this asserting party, in preference order.
		 *
		 * <p>
		 * Equivalent to the values found in &lt;SigningMethod Algorithm="..."/&gt; in the
		 * asserting party's &lt;IDPSSODescriptor&gt;.
		 * @return the list of SigningMethod Algorithms
		 * @since 5.5
		 */
		public List<String> getSigningAlgorithms() {
			return this.signingAlgorithms;
		}

		/**
		 * Get all verification {@link Saml2X509Credential}s associated with this
		 * asserting party
		 * @return all verification {@link Saml2X509Credential}s associated with this
		 * asserting party
		 * @since 5.4
		 */
		public Collection<Saml2X509Credential> getVerificationX509Credentials() {
			return this.verificationX509Credentials;
		}

		/**
		 * Get all encryption {@link Saml2X509Credential}s associated with this asserting
		 * party
		 * @return all encryption {@link Saml2X509Credential}s associated with this
		 * asserting party
		 * @since 5.4
		 */
		public Collection<Saml2X509Credential> getEncryptionX509Credentials() {
			return this.encryptionX509Credentials;
		}

		/**
		 * Get the <a href=
		 * "https://www.oasis-open.org/committees/download.php/51890/SAML%20MD%20simplified%20overview.pdf#2.5%20Endpoint">SingleSignOnService</a>
		 * Location.
		 *
		 * <p>
		 * Equivalent to the value found in &lt;SingleSignOnService Location="..."/&gt; in
		 * the asserting party's &lt;IDPSSODescriptor&gt;.
		 * @return the SingleSignOnService Location
		 */
		public String getSingleSignOnServiceLocation() {
			return this.singleSignOnServiceLocation;
		}

		/**
		 * Get the <a href=
		 * "https://www.oasis-open.org/committees/download.php/51890/SAML%20MD%20simplified%20overview.pdf#2.5%20Endpoint">SingleSignOnService</a>
		 * Binding.
		 *
		 * <p>
		 * Equivalent to the value found in &lt;SingleSignOnService Binding="..."/&gt; in
		 * the asserting party's &lt;IDPSSODescriptor&gt;.
		 * @return the SingleSignOnService Location
		 */
		public Saml2MessageBinding getSingleSignOnServiceBinding() {
			return this.singleSignOnServiceBinding;
		}

		/**
		 * Get the <a href=
		 * "https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf#page=7">SingleLogoutService
		 * Location</a>
		 *
		 * <p>
		 * Equivalent to the value found in &lt;SingleLogoutService Location="..."/&gt; in
		 * the asserting party's &lt;IDPSSODescriptor&gt;.
		 * @return the SingleLogoutService Location
		 * @since 5.6
		 */
		public String getSingleLogoutServiceLocation() {
			return this.singleLogoutServiceLocation;
		}

		/**
		 * Get the <a href=
		 * "https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf#page=7">SingleLogoutService
		 * Response Location</a>
		 *
		 * <p>
		 * Equivalent to the value found in &lt;SingleLogoutService Location="..."/&gt; in
		 * the asserting party's &lt;IDPSSODescriptor&gt;.
		 * @return the SingleLogoutService Response Location
		 * @since 5.6
		 */
		public String getSingleLogoutServiceResponseLocation() {
			return this.singleLogoutServiceResponseLocation;
		}

		/**
		 * Get the <a href=
		 * "https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf#page=7">SingleLogoutService
		 * Binding</a>
		 *
		 * <p>
		 * Equivalent to the value found in &lt;SingleLogoutService Binding="..."/&gt; in
		 * the asserting party's &lt;IDPSSODescriptor&gt;.
		 * @return the SingleLogoutService Binding
		 * @since 5.6
		 */
		public Saml2MessageBinding getSingleLogoutServiceBinding() {
			return this.singleLogoutServiceBinding;
		}

		public static class Builder {

			private String entityId;

			private boolean wantAuthnRequestsSigned = true;

			private List<String> signingAlgorithms = new ArrayList<>();

			private Collection<Saml2X509Credential> verificationX509Credentials = new LinkedHashSet<>();

			private Collection<Saml2X509Credential> encryptionX509Credentials = new LinkedHashSet<>();

			private String singleSignOnServiceLocation;

			private Saml2MessageBinding singleSignOnServiceBinding = Saml2MessageBinding.REDIRECT;

			private String singleLogoutServiceLocation;

			private String singleLogoutServiceResponseLocation;

			private Saml2MessageBinding singleLogoutServiceBinding = Saml2MessageBinding.REDIRECT;

			/**
			 * Set the asserting party's <a href=
			 * "https://www.oasis-open.org/committees/download.php/51890/SAML%20MD%20simplified%20overview.pdf#2.9%20EntityDescriptor">EntityID</a>.
			 * Equivalent to the value found in the asserting party's &lt;EntityDescriptor
			 * EntityID="..."/&gt;
			 * @param entityId the asserting party's EntityID
			 * @return the {@link AssertingPartyDetails.Builder} for further configuration
			 */
			public Builder entityId(String entityId) {
				this.entityId = entityId;
				return this;
			}

			/**
			 * Set the WantAuthnRequestsSigned setting, indicating the asserting party's
			 * preference that relying parties should sign the AuthnRequest before
			 * sending.
			 * @param wantAuthnRequestsSigned the WantAuthnRequestsSigned setting
			 * @return the {@link AssertingPartyDetails.Builder} for further configuration
			 */
			public Builder wantAuthnRequestsSigned(boolean wantAuthnRequestsSigned) {
				this.wantAuthnRequestsSigned = wantAuthnRequestsSigned;
				return this;
			}

			/**
			 * Apply this {@link Consumer} to the list of SigningMethod Algorithms
			 * @param signingMethodAlgorithmsConsumer a {@link Consumer} of the list of
			 * SigningMethod Algorithms
			 * @return this {@link AssertingPartyDetails.Builder} for further
			 * configuration
			 * @since 5.5
			 */
			public Builder signingAlgorithms(Consumer<List<String>> signingMethodAlgorithmsConsumer) {
				signingMethodAlgorithmsConsumer.accept(this.signingAlgorithms);
				return this;
			}

			/**
			 * Apply this {@link Consumer} to the list of {@link Saml2X509Credential}s
			 * @param credentialsConsumer a {@link Consumer} of the {@link List} of
			 * {@link Saml2X509Credential}s
			 * @return the {@link RelyingPartyRegistration.Builder} for further
			 * configuration
			 * @since 5.4
			 */
			public Builder verificationX509Credentials(Consumer<Collection<Saml2X509Credential>> credentialsConsumer) {
				credentialsConsumer.accept(this.verificationX509Credentials);
				return this;
			}

			/**
			 * Apply this {@link Consumer} to the list of {@link Saml2X509Credential}s
			 * @param credentialsConsumer a {@link Consumer} of the {@link List} of
			 * {@link Saml2X509Credential}s
			 * @return the {@link RelyingPartyRegistration.Builder} for further
			 * configuration
			 * @since 5.4
			 */
			public Builder encryptionX509Credentials(Consumer<Collection<Saml2X509Credential>> credentialsConsumer) {
				credentialsConsumer.accept(this.encryptionX509Credentials);
				return this;
			}

			/**
			 * Set the <a href=
			 * "https://www.oasis-open.org/committees/download.php/51890/SAML%20MD%20simplified%20overview.pdf#2.5%20Endpoint">SingleSignOnService</a>
			 * Location.
			 *
			 * <p>
			 * Equivalent to the value found in &lt;SingleSignOnService
			 * Location="..."/&gt; in the asserting party's &lt;IDPSSODescriptor&gt;.
			 * @param singleSignOnServiceLocation the SingleSignOnService Location
			 * @return the {@link AssertingPartyDetails.Builder} for further configuration
			 */
			public Builder singleSignOnServiceLocation(String singleSignOnServiceLocation) {
				this.singleSignOnServiceLocation = singleSignOnServiceLocation;
				return this;
			}

			/**
			 * Set the <a href=
			 * "https://www.oasis-open.org/committees/download.php/51890/SAML%20MD%20simplified%20overview.pdf#2.5%20Endpoint">SingleSignOnService</a>
			 * Binding.
			 *
			 * <p>
			 * Equivalent to the value found in &lt;SingleSignOnService Binding="..."/&gt;
			 * in the asserting party's &lt;IDPSSODescriptor&gt;.
			 * @param singleSignOnServiceBinding the SingleSignOnService Binding
			 * @return the {@link AssertingPartyDetails.Builder} for further configuration
			 */
			public Builder singleSignOnServiceBinding(Saml2MessageBinding singleSignOnServiceBinding) {
				this.singleSignOnServiceBinding = singleSignOnServiceBinding;
				return this;
			}

			/**
			 * Set the <a href=
			 * "https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf#page=7">SingleLogoutService
			 * Location</a>
			 *
			 * <p>
			 * Equivalent to the value found in &lt;SingleLogoutService
			 * Location="..."/&gt; in the asserting party's &lt;IDPSSODescriptor&gt;.
			 * @param singleLogoutServiceLocation the SingleLogoutService Location
			 * @return the {@link AssertingPartyDetails.Builder} for further configuration
			 * @since 5.6
			 */
			public Builder singleLogoutServiceLocation(String singleLogoutServiceLocation) {
				this.singleLogoutServiceLocation = singleLogoutServiceLocation;
				return this;
			}

			/**
			 * Set the <a href=
			 * "https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf#page=7">SingleLogoutService
			 * Response Location</a>
			 *
			 * <p>
			 * Equivalent to the value found in &lt;SingleLogoutService
			 * ResponseLocation="..."/&gt; in the asserting party's
			 * &lt;IDPSSODescriptor&gt;.
			 * @param singleLogoutServiceResponseLocation the SingleLogoutService Response
			 * Location
			 * @return the {@link AssertingPartyDetails.Builder} for further configuration
			 * @since 5.6
			 */
			public Builder singleLogoutServiceResponseLocation(String singleLogoutServiceResponseLocation) {
				this.singleLogoutServiceResponseLocation = singleLogoutServiceResponseLocation;
				return this;
			}

			/**
			 * Set the <a href=
			 * "https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf#page=7">SingleLogoutService
			 * Binding</a>
			 *
			 * <p>
			 * Equivalent to the value found in &lt;SingleLogoutService Binding="..."/&gt;
			 * in the asserting party's &lt;IDPSSODescriptor&gt;.
			 * @param singleLogoutServiceBinding the SingleLogoutService Binding
			 * @return the {@link AssertingPartyDetails.Builder} for further configuration
			 * @since 5.6
			 */
			public Builder singleLogoutServiceBinding(Saml2MessageBinding singleLogoutServiceBinding) {
				this.singleLogoutServiceBinding = singleLogoutServiceBinding;
				return this;
			}

			/**
			 * Creates an immutable ProviderDetails object representing the configuration
			 * for an Identity Provider, IDP
			 * @return immutable ProviderDetails object
			 */
			public AssertingPartyDetails build() {
				List<String> signingAlgorithms = this.signingAlgorithms.isEmpty()
						? Collections.singletonList(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256)
						: Collections.unmodifiableList(this.signingAlgorithms);

				return new AssertingPartyDetails(this.entityId, this.wantAuthnRequestsSigned, signingAlgorithms,
						this.verificationX509Credentials, this.encryptionX509Credentials,
						this.singleSignOnServiceLocation, this.singleSignOnServiceBinding,
						this.singleLogoutServiceLocation, this.singleLogoutServiceResponseLocation,
						this.singleLogoutServiceBinding);
			}

		}

	}

	public static final class Builder {

		private String registrationId;

		private String entityId = "{baseUrl}/saml2/service-provider-metadata/{registrationId}";

		private Collection<Saml2X509Credential> signingX509Credentials = new LinkedHashSet<>();

		private Collection<Saml2X509Credential> decryptionX509Credentials = new LinkedHashSet<>();

		private String assertionConsumerServiceLocation = "{baseUrl}/login/saml2/sso/{registrationId}";

		private Saml2MessageBinding assertionConsumerServiceBinding = Saml2MessageBinding.POST;

		private String singleLogoutServiceLocation;

		private String singleLogoutServiceResponseLocation;

		private Collection<Saml2MessageBinding> singleLogoutServiceBindings = new LinkedHashSet<>();

		private String nameIdFormat = null;

		private AssertingPartyDetails.Builder assertingPartyDetailsBuilder = new AssertingPartyDetails.Builder();

		private Builder(String registrationId) {
			this.registrationId = registrationId;
		}

		/**
		 * Sets the {@code registrationId} template. Often be used in URL paths
		 * @param id registrationId for this object, should be unique
		 * @return this object
		 */
		public Builder registrationId(String id) {
			this.registrationId = id;
			return this;
		}

		/**
		 * Set the relying party's <a href=
		 * "https://www.oasis-open.org/committees/download.php/51890/SAML%20MD%20simplified%20overview.pdf#2.9%20EntityDescriptor">EntityID</a>.
		 * Equivalent to the value found in the relying party's &lt;EntityDescriptor
		 * EntityID="..."/&gt;
		 *
		 * This value may contain a number of placeholders. They are {@code baseUrl},
		 * {@code registrationId}, {@code baseScheme}, {@code baseHost}, and
		 * {@code basePort}.
		 * @param entityId the relying party's EntityID
		 * @return the {@link Builder} for further configuration
		 * @since 5.4
		 */
		public Builder entityId(String entityId) {
			this.entityId = entityId;
			return this;
		}

		/**
		 * Apply this {@link Consumer} to the {@link Collection} of
		 * {@link Saml2X509Credential}s for the purposes of modifying the
		 * {@link Collection}
		 * @param credentialsConsumer - the {@link Consumer} for modifying the
		 * {@link Collection}
		 * @return the {@link Builder} for further configuration
		 * @since 5.4
		 */
		public Builder signingX509Credentials(Consumer<Collection<Saml2X509Credential>> credentialsConsumer) {
			credentialsConsumer.accept(this.signingX509Credentials);
			return this;
		}

		/**
		 * Apply this {@link Consumer} to the {@link Collection} of
		 * {@link Saml2X509Credential}s for the purposes of modifying the
		 * {@link Collection}
		 * @param credentialsConsumer - the {@link Consumer} for modifying the
		 * {@link Collection}
		 * @return the {@link Builder} for further configuration
		 * @since 5.4
		 */
		public Builder decryptionX509Credentials(Consumer<Collection<Saml2X509Credential>> credentialsConsumer) {
			credentialsConsumer.accept(this.decryptionX509Credentials);
			return this;
		}

		/**
		 * Set the <a href=
		 * "https://www.oasis-open.org/committees/download.php/51890/SAML%20MD%20simplified%20overview.pdf#2.3%20AttributeConsumingService">
		 * AssertionConsumerService</a> Location.
		 *
		 * <p>
		 * Equivalent to the value found in &lt;AssertionConsumerService
		 * Location="..."/&gt; in the relying party's &lt;SPSSODescriptor&gt;
		 *
		 * <p>
		 * This value may contain a number of placeholders. They are {@code baseUrl},
		 * {@code registrationId}, {@code baseScheme}, {@code baseHost}, and
		 * {@code basePort}.
		 * @param assertionConsumerServiceLocation the AssertionConsumerService location
		 * @return the {@link Builder} for further configuration
		 * @since 5.4
		 */
		public Builder assertionConsumerServiceLocation(String assertionConsumerServiceLocation) {
			this.assertionConsumerServiceLocation = assertionConsumerServiceLocation;
			return this;
		}

		/**
		 * Set the <a href=
		 * "https://www.oasis-open.org/committees/download.php/51890/SAML%20MD%20simplified%20overview.pdf#2.3%20AttributeConsumingService">
		 * AssertionConsumerService</a> Binding.
		 *
		 * <p>
		 * Equivalent to the value found in &lt;AssertionConsumerService
		 * Binding="..."/&gt; in the relying party's &lt;SPSSODescriptor&gt;
		 * @param assertionConsumerServiceBinding the AssertionConsumerService binding
		 * @return the {@link Builder} for further configuration
		 * @since 5.4
		 */
		public Builder assertionConsumerServiceBinding(Saml2MessageBinding assertionConsumerServiceBinding) {
			this.assertionConsumerServiceBinding = assertionConsumerServiceBinding;
			return this;
		}

		/**
		 * Set the <a href=
		 * "https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf#page=7">SingleLogoutService
		 * Binding</a>
		 *
		 * <p>
		 * Equivalent to the value found in &lt;SingleLogoutService Binding="..."/&gt; in
		 * the relying party's &lt;SPSSODescriptor&gt;.
		 * @param singleLogoutServiceBinding the SingleLogoutService Binding
		 * @return the {@link Builder} for further configuration
		 * @since 5.6
		 */
		public Builder singleLogoutServiceBinding(Saml2MessageBinding singleLogoutServiceBinding) {
			return this.singleLogoutServiceBindings((saml2MessageBindings) -> {
				saml2MessageBindings.clear();
				saml2MessageBindings.add(singleLogoutServiceBinding);
			});
		}

		/**
		 * Apply this {@link Consumer} to the {@link Collection} of
		 * {@link Saml2MessageBinding}s for the purposes of modifying the <a href=
		 * "https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf#page=7">SingleLogoutService
		 * Binding</a> {@link Collection}.
		 *
		 * <p>
		 * Equivalent to the value found in &lt;SingleLogoutService Binding="..."/&gt; in
		 * the relying party's &lt;SPSSODescriptor&gt;.
		 * @param bindingsConsumer - the {@link Consumer} for modifying the
		 * {@link Collection}
		 * @return the {@link Builder} for further configuration
		 * @since 5.8
		 */
		public Builder singleLogoutServiceBindings(Consumer<Collection<Saml2MessageBinding>> bindingsConsumer) {
			bindingsConsumer.accept(this.singleLogoutServiceBindings);
			return this;
		}

		/**
		 * Set the <a href=
		 * "https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf#page=7">SingleLogoutService
		 * Location</a>
		 *
		 * <p>
		 * Equivalent to the value found in &lt;SingleLogoutService Location="..."/&gt; in
		 * the relying party's &lt;SPSSODescriptor&gt;.
		 * @param singleLogoutServiceLocation the SingleLogoutService Location
		 * @return the {@link Builder} for further configuration
		 * @since 5.6
		 */
		public Builder singleLogoutServiceLocation(String singleLogoutServiceLocation) {
			this.singleLogoutServiceLocation = singleLogoutServiceLocation;
			return this;
		}

		/**
		 * Set the <a href=
		 * "https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf#page=7">SingleLogoutService
		 * Response Location</a>
		 *
		 * <p>
		 * Equivalent to the value found in &lt;SingleLogoutService
		 * ResponseLocation="..."/&gt; in the relying party's &lt;SPSSODescriptor&gt;.
		 * @param singleLogoutServiceResponseLocation the SingleLogoutService Response
		 * Location
		 * @return the {@link Builder} for further configuration
		 * @since 5.6
		 */
		public Builder singleLogoutServiceResponseLocation(String singleLogoutServiceResponseLocation) {
			this.singleLogoutServiceResponseLocation = singleLogoutServiceResponseLocation;
			return this;
		}

		/**
		 * Set the NameID format
		 * @param nameIdFormat
		 * @return the {@link Builder} for further configuration
		 * @since 5.7
		 */
		public Builder nameIdFormat(String nameIdFormat) {
			this.nameIdFormat = nameIdFormat;
			return this;
		}

		/**
		 * Apply this {@link Consumer} to further configure the Asserting Party details
		 * @param assertingPartyDetails The {@link Consumer} to apply
		 * @return the {@link Builder} for further configuration
		 * @since 5.4
		 */
		public Builder assertingPartyDetails(Consumer<AssertingPartyDetails.Builder> assertingPartyDetails) {
			assertingPartyDetails.accept(this.assertingPartyDetailsBuilder);
			return this;
		}

		/**
		 * Constructs a RelyingPartyRegistration object based on the builder
		 * configurations
		 * @return a RelyingPartyRegistration instance
		 */
		public RelyingPartyRegistration build() {
			if (this.singleLogoutServiceResponseLocation == null) {
				this.singleLogoutServiceResponseLocation = this.singleLogoutServiceLocation;
			}

			if (this.singleLogoutServiceBindings.isEmpty()) {
				this.singleLogoutServiceBindings.add(Saml2MessageBinding.POST);
			}

			return new RelyingPartyRegistration(this.registrationId, this.entityId,
					this.assertionConsumerServiceLocation, this.assertionConsumerServiceBinding,
					this.singleLogoutServiceLocation, this.singleLogoutServiceResponseLocation,
					this.singleLogoutServiceBindings, this.assertingPartyDetailsBuilder.build(), this.nameIdFormat,
					this.decryptionX509Credentials, this.signingX509Credentials);
		}

	}

}
