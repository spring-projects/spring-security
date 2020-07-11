/*
 * Copyright 2002-2019 the original author or authors.
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
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;

import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.security.saml2.credentials.Saml2X509Credential.Saml2X509CredentialType;
import org.springframework.util.Assert;

/**
 * Represents a configured relying party (aka Service Provider) and asserting party (aka Identity Provider) pair.
 *
 * <p>
 * Each RP/AP pair is uniquely identified using a {@code registrationId}, an arbitrary string.
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
 *	String assertingPartyEntityId = "https://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php";
 *	String singleSignOnServiceLocation = "https://simplesaml-for-spring-saml.cfapps.io/saml2/idp/SSOService.php";
 * 	Saml2X509Credential assertingPartyVerificationCredential = ...;
 *
 *
 *	RelyingPartyRegistration rp = RelyingPartyRegistration.withRegistrationId(registrationId)
 * 			.entityId(relyingPartyEntityId)
 * 			.assertionConsumerServiceLocation(assertingConsumerServiceLocation)
 * 		 	.credentials(c -> c.add(relyingPartySigningCredential))
 * 			.assertingPartyDetails(details -> details
 * 				.entityId(assertingPartyEntityId));
 * 				.singleSignOnServiceLocation(singleSignOnServiceLocation))
 * 				.credentials(c -> c.add(assertingPartyVerificationCredential))
 * 			.build();
 * </pre>
 *
 * @since 5.2
 * @author Filip Hanik
 * @author Josh Cummings
 */
public class RelyingPartyRegistration {

	private final String registrationId;
	private final String entityId;
	private final String assertionConsumerServiceLocation;
	private final ProviderDetails providerDetails;
	private final List<Saml2X509Credential> credentials;

	private RelyingPartyRegistration(
			String registrationId,
			String entityId,
			String assertionConsumerServiceLocation,
			ProviderDetails providerDetails,
			List<Saml2X509Credential> credentials) {

		Assert.hasText(registrationId, "registrationId cannot be empty");
		Assert.hasText(entityId, "entityId cannot be empty");
		Assert.hasText(assertionConsumerServiceLocation, "assertionConsumerServiceLocation cannot be empty");
		Assert.notNull(providerDetails, "providerDetails cannot be null");
		Assert.notEmpty(credentials, "credentials cannot be empty");
		for (Saml2X509Credential c : credentials) {
			Assert.notNull(c, "credentials cannot contain null elements");
		}
		this.registrationId = registrationId;
		this.entityId = entityId;
		this.assertionConsumerServiceLocation = assertionConsumerServiceLocation;
		this.providerDetails = providerDetails;
		this.credentials = Collections.unmodifiableList(new LinkedList<>(credentials));
	}

	/**
	 * Get the unique registration id for this RP/AP pair
	 *
	 * @return the unique registration id for this RP/AP pair
	 */
	public String getRegistrationId() {
		return this.registrationId;
	}

	/**
	 * Get the relying party's
	 * <a href="https://wiki.shibboleth.net/confluence/display/CONCEPT/EntityNaming">EntityID</a>.
	 *
	 * <p>
	 * Equivalent to the value found in the relying party's
	 * &lt;EntityDescriptor EntityID="..."/&gt;
	 *
	 * <p>
	 * This value may contain a number of placeholders, which need to be
	 * resolved before use. They are {@code baseUrl}, {@code registrationId},
	 * {@code baseScheme}, {@code baseHost}, and {@code basePort}.
	 *
	 * @return the relying party's EntityID
	 * @since 5.4
	 */
	public String getEntityId() {
		return this.entityId;
	}

	/**
	 * Get the AssertionConsumerService Location.
	 * Equivalent to the value found in &lt;AssertionConsumerService Location="..."/&gt;
	 * in the relying party's &lt;SPSSODescriptor&gt;.
	 *
	 * This value may contain a number of placeholders, which need to be
	 * resolved before use. They are {@code baseUrl}, {@code registrationId},
	 * {@code baseScheme}, {@code baseHost}, and {@code basePort}.
	 *
	 * @return the AssertionConsumerService Location
	 * @since 5.4
	 */
	public String getAssertionConsumerServiceLocation() {
		return this.assertionConsumerServiceLocation;
	}

	/**
	 * Get the configuration details for the Asserting Party
	 *
	 * @return the {@link AssertingPartyDetails}
	 * @since 5.4
	 */
	public AssertingPartyDetails getAssertingPartyDetails() {
		return this.providerDetails.assertingPartyDetails;
	}

	/**
	 * Returns the entity ID of the IDP, the asserting party.
	 * @return entity ID of the asserting party
	 * @deprecated use {@link AssertingPartyDetails#getEntityId} from {@link #getAssertingPartyDetails}
	 */
	@Deprecated
	public String getRemoteIdpEntityId() {
		return this.providerDetails.getEntityId();
	}

	/**
	 * returns the URL template for which ACS URL authentication requests should contain
	 * Possible variables are {@code baseUrl}, {@code registrationId},
	 * {@code baseScheme}, {@code baseHost}, and {@code basePort}.
	 * @return string containing the ACS URL template, with or without variables present
	 * @deprecated Use {@link #getAssertionConsumerServiceLocation} instead
	 */
	@Deprecated
	public String getAssertionConsumerServiceUrlTemplate() {
		return this.assertionConsumerServiceLocation;
	}

	/**
	 * Contains the URL for which to send the SAML 2 Authentication Request to initiate
	 * a single sign on flow.
	 * @return a IDP URL that accepts REDIRECT or POST binding for authentication requests
	 * @deprecated use {@link AssertingPartyDetails#getSingleSignOnServiceLocation} from {@link #getAssertingPartyDetails}
	 */
	@Deprecated
	public String getIdpWebSsoUrl() {
		return this.getAssertingPartyDetails().getSingleSignOnServiceLocation();
	}

	/**
	 * Returns specific configuration around the Identity Provider SSO endpoint
	 * @return the IDP SSO endpoint configuration
	 * @since 5.3
	 * @deprecated Use {@link #getAssertingPartyDetails} instead
	 */
	@Deprecated
	public ProviderDetails getProviderDetails() {
		return this.providerDetails;
	}

	/**
	 * The local relying party, or Service Provider, can generate it's entity ID based on
	 * possible variables of {@code baseUrl}, {@code registrationId},
	 * {@code baseScheme}, {@code baseHost}, and {@code basePort}, for example
	 * {@code {baseUrl}/saml2/service-provider-metadata/{registrationId}}
	 * @return a string containing the entity ID or entity ID template
	 * @deprecated Use {@link #getEntityId} instead
	 */
	@Deprecated
	public String getLocalEntityIdTemplate() {
		return this.entityId;
	}

	/**
	 * Returns a list of configured credentials to be used in message exchanges between relying party, SP, and
	 * asserting party, IDP.
	 * @return a list of credentials
	 */
	public List<Saml2X509Credential> getCredentials() {
		return this.credentials;
	}

	/**
	 * @return a filtered list containing only credentials of type
	 * {@link Saml2X509CredentialType#VERIFICATION}.
	 * Returns an empty list of credentials are not found
	 */
	public List<Saml2X509Credential> getVerificationCredentials() {
		return filterCredentials(c -> c.isSignatureVerficationCredential());
	}

	/**
	 * @return a filtered list containing only credentials of type
	 * {@link Saml2X509CredentialType#SIGNING}.
	 * Returns an empty list of credentials are not found
	 */
	public List<Saml2X509Credential> getSigningCredentials() {
		return filterCredentials(c -> c.isSigningCredential());
	}

	/**
	 * @return a filtered list containing only credentials of type
	 * {@link Saml2X509CredentialType#ENCRYPTION}.
	 * Returns an empty list of credentials are not found
	 */
	public List<Saml2X509Credential> getEncryptionCredentials() {
		return filterCredentials(c -> c.isEncryptionCredential());
	}

	/**
	 * @return a filtered list containing only credentials of type
	 * {@link Saml2X509CredentialType#DECRYPTION}.
	 * Returns an empty list of credentials are not found
	 */
	public List<Saml2X509Credential> getDecryptionCredentials() {
		return filterCredentials(c -> c.isDecryptionCredential());
	}

	private List<Saml2X509Credential> filterCredentials(Function<Saml2X509Credential, Boolean> filter) {
		List<Saml2X509Credential> result = new LinkedList<>();
		for (Saml2X509Credential c : getCredentials()) {
			if (filter.apply(c)) {
				result.add(c);
			}
		}
		return result;
	}

	/**
	 * Creates a {@code RelyingPartyRegistration} {@link Builder} with a known {@code registrationId}
	 * @param registrationId a string identifier for the {@code RelyingPartyRegistration}
	 * @return {@code Builder} to create a {@code RelyingPartyRegistration} object
	 */
	public static Builder withRegistrationId(String registrationId) {
		Assert.hasText(registrationId, "registrationId cannot be empty");
		return new Builder(registrationId);
	}

	/**
	 * Creates a {@code RelyingPartyRegistration} {@link Builder} based on an existing object
	 * @param registration the {@code RelyingPartyRegistration}
	 * @return {@code Builder} to create a {@code RelyingPartyRegistration} object
	 */
	public static Builder withRelyingPartyRegistration(RelyingPartyRegistration registration) {
		Assert.notNull(registration, "registration cannot be null");
		return withRegistrationId(registration.getRegistrationId())
				.entityId(registration.getEntityId())
				.assertionConsumerServiceLocation(registration.getAssertionConsumerServiceLocation())
				.assertingPartyDetails(c -> c
					.entityId(registration.getAssertingPartyDetails().getEntityId())
					.wantAuthnRequestsSigned(registration.getAssertingPartyDetails().getWantAuthnRequestsSigned())
					.singleSignOnServiceLocation(registration.getAssertingPartyDetails().getSingleSignOnServiceLocation())
					.singleSignOnServiceBinding(registration.getAssertingPartyDetails().getSingleSignOnServiceBinding())
					.nameIdFormat(registration.getAssertingPartyDetails().getNameIdFormat())
				)
				.credentials(c -> c.addAll(registration.getCredentials()));
	}


	/**
	 * The configuration metadata of the Asserting party
	 *
	 * @since 5.4
	 */
	public final static class AssertingPartyDetails {
		private final String entityId;
		private final boolean wantAuthnRequestsSigned;
		private final String singleSignOnServiceLocation;
		private final String nameIdFormat;
		private final Saml2MessageBinding singleSignOnServiceBinding;

		private AssertingPartyDetails(
				String entityId,
				boolean wantAuthnRequestsSigned,
				String singleSignOnServiceLocation,
				String nameIdFormat,
				Saml2MessageBinding singleSignOnServiceBinding) {

			Assert.hasText(entityId, "entityId cannot be null or empty");
			Assert.notNull(singleSignOnServiceLocation, "singleSignOnServiceLocation cannot be null");
			Assert.notNull(singleSignOnServiceBinding, "singleSignOnServiceBinding cannot be null");
			this.entityId = entityId;
			this.wantAuthnRequestsSigned = wantAuthnRequestsSigned;
			this.singleSignOnServiceLocation = singleSignOnServiceLocation;
			this.nameIdFormat = nameIdFormat;
			this.singleSignOnServiceBinding = singleSignOnServiceBinding;
		}

		/**
		 * Get the asserting party's
		 * <a href="https://wiki.shibboleth.net/confluence/display/CONCEPT/EntityNaming">EntityID</a>.
		 *
		 * <p>
		 * Equivalent to the value found in the asserting party's
		 * &lt;EntityDescriptor EntityID="..."/&gt;
		 *
		 * <p>
		 * This value may contain a number of placeholders, which need to be
		 * resolved before use. They are {@code baseUrl}, {@code registrationId},
		 * {@code baseScheme}, {@code baseHost}, and {@code basePort}.
		 *
		 * @return the asserting party's EntityID
		 */
		public String getEntityId() {
			return this.entityId;
		}

		/**
		 * Get the WantAuthnRequestsSigned setting, indicating the asserting party's preference that
		 * relying parties should sign the AuthnRequest before sending.
		 *
		 * @return the WantAuthnRequestsSigned value
		 */
		public boolean getWantAuthnRequestsSigned() {
			return this.wantAuthnRequestsSigned;
		}

		/**
		 * Get the
		 * <a href="https://wiki.shibboleth.net/confluence/display/CONCEPT/MetadataForIdP#MetadataForIdP-SingleSign-OnServices">SingleSignOnService</a>
		 * Location.
		 *
		 * <p>
		 * Equivalent to the value found in &lt;SingleSignOnService Location="..."/&gt;
		 * in the asserting party's &lt;IDPSSODescriptor&gt;.
		 *
		 * @return the SingleSignOnService Location
		 */
		public String getSingleSignOnServiceLocation() {
			return this.singleSignOnServiceLocation;
		}

		/**
		 * Get the NameIDFormat setting, indicating which user property should be used as a NameID Format attribute
		 *
		 * @return the NameIdFormat value
		 */
		public String getNameIdFormat() {
			return nameIdFormat;
		}

		/**
		 * Get the
		 * <a href="https://wiki.shibboleth.net/confluence/display/CONCEPT/MetadataForIdP#MetadataForIdP-SingleSign-OnServices">SingleSignOnService</a>
		 * Binding.
		 *
		 * <p>
		 * Equivalent to the value found in &lt;SingleSignOnService Binding="..."/&gt;
		 * in the asserting party's &lt;IDPSSODescriptor&gt;.
		 *
		 * @return the SingleSignOnService Location
		 */
		public Saml2MessageBinding getSingleSignOnServiceBinding() {
			return this.singleSignOnServiceBinding;
		}

		public final static class Builder {
			private String entityId;
			private boolean wantAuthnRequestsSigned = true;
			private String singleSignOnServiceLocation;
			private String nameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
			private Saml2MessageBinding singleSignOnServiceBinding = Saml2MessageBinding.REDIRECT;

			/**
			 * Set the asserting party's
			 * <a href="https://wiki.shibboleth.net/confluence/display/CONCEPT/EntityNaming">EntityID</a>.
			 * Equivalent to the value found in the asserting party's
			 * &lt;EntityDescriptor EntityID="..."/&gt;
			 *
			 * @param entityId the asserting party's EntityID
			 * @return the {@link ProviderDetails.Builder} for further configuration
			 */
			public Builder entityId(String entityId) {
				this.entityId = entityId;
				return this;
			}

			/**
			 * Set the WantAuthnRequestsSigned setting, indicating the asserting party's preference that
			 * relying parties should sign the AuthnRequest before sending.
			 *
			 * @param wantAuthnRequestsSigned the WantAuthnRequestsSigned setting
			 * @return the {@link ProviderDetails.Builder} for further configuration
			 */
			public Builder wantAuthnRequestsSigned(boolean wantAuthnRequestsSigned) {
				this.wantAuthnRequestsSigned = wantAuthnRequestsSigned;
				return this;
			}

			/**
			 * Set the
			 * <a href="https://wiki.shibboleth.net/confluence/display/CONCEPT/MetadataForIdP#MetadataForIdP-SingleSign-OnServices">SingleSignOnService</a>
			 * Location.
			 *
			 * <p>
			 * Equivalent to the value found in &lt;SingleSignOnService Location="..."/&gt;
			 * in the asserting party's &lt;IDPSSODescriptor&gt;.
			 *
			 * @param singleSignOnServiceLocation the SingleSignOnService Location
			 * @return the {@link ProviderDetails.Builder} for further configuration
			 */
			public Builder singleSignOnServiceLocation(String singleSignOnServiceLocation) {
				this.singleSignOnServiceLocation = singleSignOnServiceLocation;
				return this;
			}

			/**
			 * Set the preference for name identifier returned by IdP.
			 * See <a href="https://wiki.shibboleth.net/confluence/display/SHIB/NameIdentifierFormat">for possible values</a>
			 *
			 * @param nameIdFormat the name identifier
			 * @return the {@link ProviderDetails.Builder} for further configuration
			 */
			public Builder nameIdFormat(String nameIdFormat) {
				this.nameIdFormat = nameIdFormat;
				return this;
			}

			/**
			 * Set the
			 * <a href="https://wiki.shibboleth.net/confluence/display/CONCEPT/MetadataForIdP#MetadataForIdP-SingleSign-OnServices">SingleSignOnService</a>
			 * Binding.
			 *
			 * <p>
			 * Equivalent to the value found in &lt;SingleSignOnService Binding="..."/&gt;
			 * in the asserting party's &lt;IDPSSODescriptor&gt;.
			 *
			 * @param singleSignOnServiceBinding the SingleSignOnService Binding
			 * @return the {@link ProviderDetails.Builder} for further configuration
			 */
			public Builder singleSignOnServiceBinding(Saml2MessageBinding singleSignOnServiceBinding) {
				this.singleSignOnServiceBinding = singleSignOnServiceBinding;
				return this;
			}

			/**
			 * Creates an immutable ProviderDetails object representing the configuration for an Identity Provider, IDP
			 * @return immutable ProviderDetails object
			 */
			public AssertingPartyDetails build() {
				return new AssertingPartyDetails(
						this.entityId,
						this.wantAuthnRequestsSigned,
						this.singleSignOnServiceLocation,
						this.nameIdFormat,
						this.singleSignOnServiceBinding
				);
			}
		}
	}

	/**
	 * Configuration for IDP SSO endpoint configuration
	 * @since 5.3
	 * @deprecated Use {@link AssertingPartyDetails} instead
	 */
	@Deprecated
	public final static class ProviderDetails {
		private final AssertingPartyDetails assertingPartyDetails;

		private ProviderDetails(AssertingPartyDetails assertingPartyDetails) {
			Assert.notNull("assertingPartyDetails cannot be null");
			this.assertingPartyDetails = assertingPartyDetails;
		}

		/**
		 * Returns the entity ID of the Identity Provider
		 * @return the entity ID of the IDP
		 */
		public String getEntityId() {
			return this.assertingPartyDetails.getEntityId();
		}

		/**
		 * Contains the URL for which to send the SAML 2 Authentication Request to initiate
		 * a single sign on flow.
		 * @return a IDP URL that accepts REDIRECT or POST binding for authentication requests
		 */
		public String getWebSsoUrl() {
			return this.assertingPartyDetails.getSingleSignOnServiceLocation();
		}

		/**
		 * @return {@code true} if AuthNRequests from this relying party to the IDP should be signed
		 * {@code false} if no signature is required.
		 */
		public boolean isSignAuthNRequest() {
			return this.assertingPartyDetails.getWantAuthnRequestsSigned();
		}

		/**
		 * @return the type of SAML 2 Binding the AuthNRequest should be sent on
		 */
		public Saml2MessageBinding getBinding() {
			return this.assertingPartyDetails.getSingleSignOnServiceBinding();
		}

		/**
		 * Builder for IDP SSO endpoint configuration
		 * @since 5.3
		 * @deprecated Use {@link AssertingPartyDetails.Builder} instead
		 */
		@Deprecated
		public final static class Builder {
			private final AssertingPartyDetails.Builder assertingPartyDetailsBuilder =
					new AssertingPartyDetails.Builder();

			/**
			 * Set the asserting party's
			 * <a href="https://wiki.shibboleth.net/confluence/display/CONCEPT/EntityNaming">EntityID</a>.
			 * Equivalent to the value found in the asserting party's
			 * &lt;EntityDescriptor EntityID="..."/&gt;
			 *
			 * @param entityId the asserting party's EntityID
			 * @return the {@link Builder} for further configuration
			 * @since 5.4
			 */
			public Builder entityId(String entityId) {
				this.assertingPartyDetailsBuilder.entityId(entityId);
				return this;
			}

			/**
			 * Sets the {@code SSO URL} for the remote asserting party, the Identity Provider.
			 *
			 * @param url - a URL that accepts authentication requests via REDIRECT or POST bindings
			 * @return this object
			 */
			public Builder webSsoUrl(String url) {
				this.assertingPartyDetailsBuilder.singleSignOnServiceLocation(url);
				return this;
			}

			/**
			 * Set to true if the AuthNRequest message should be signed
			 *
			 * @param signAuthNRequest true if the message should be signed
			 * @return this object
			 */
			public Builder signAuthNRequest(boolean signAuthNRequest) {
				this.assertingPartyDetailsBuilder.wantAuthnRequestsSigned(signAuthNRequest);
				return this;
			}


			/**
			 * Sets the message binding to be used when sending an AuthNRequest message
			 *
			 * @param binding either {@link Saml2MessageBinding#POST} or {@link Saml2MessageBinding#REDIRECT}
			 * @return this object
			 */
			public Builder binding(Saml2MessageBinding binding) {
				this.assertingPartyDetailsBuilder.singleSignOnServiceBinding(binding);
				return this;
			}

			/**
			 * Creates an immutable ProviderDetails object representing the configuration for an Identity Provider, IDP
			 * @return immutable ProviderDetails object
			 */
			public ProviderDetails build() {
				return new ProviderDetails(this.assertingPartyDetailsBuilder.build());
			}
		}
	}

	public final static class Builder {
		private String registrationId;
		private String entityId = "{baseUrl}/saml2/service-provider-metadata/{registrationId}";
		private String assertionConsumerServiceLocation;
		private ProviderDetails.Builder providerDetails = new ProviderDetails.Builder();
		private List<Saml2X509Credential> credentials = new LinkedList<>();

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
		 * Set the relying party's
		 * <a href="https://wiki.shibboleth.net/confluence/display/CONCEPT/EntityNaming">EntityID</a>.
		 * Equivalent to the value found in the relying party's
		 * &lt;EntityDescriptor EntityID="..."/&gt;
		 *
		 * This value may contain a number of placeholders.
		 * They are {@code baseUrl}, {@code registrationId},
		 * {@code baseScheme}, {@code baseHost}, and {@code basePort}.
		 *
		 * @return the {@link Builder} for further configuration
		 * @since 5.4
		 */
		public Builder entityId(String entityId) {
			this.entityId = entityId;
			return this;
		}

		/**
		 * Set the <a href="https://wiki.shibboleth.net/confluence/display/CONCEPT/AssertionConsumerService">AssertionConsumerService</a>
		 * Location.
		 *
		 * <p>
		 * Equivalent to the value found in &lt;AssertionConsumerService Location="..."/&gt;
		 * in the relying party's &lt;SPSSODescriptor&gt;
		 *
		 * <p>
		 * This value may contain a number of placeholders.
		 * They are {@code baseUrl}, {@code registrationId},
		 * {@code baseScheme}, {@code baseHost}, and {@code basePort}.
		 *
		 * @param assertionConsumerServiceLocation
		 * @return the {@link Builder} for further configuration
		 * @since 5.4
		 */
		public Builder assertionConsumerServiceLocation(String assertionConsumerServiceLocation) {
			this.assertionConsumerServiceLocation = assertionConsumerServiceLocation;
			return this;
		}

		/**
		 * Apply this {@link Consumer} to further configure the Asserting Party details
		 *
		 * @param assertingPartyDetails The {@link Consumer} to apply
		 * @return the {@link Builder} for further configuration
		 * @since 5.4
		 */
		public Builder assertingPartyDetails(Consumer<AssertingPartyDetails.Builder> assertingPartyDetails) {
			assertingPartyDetails.accept(this.providerDetails.assertingPartyDetailsBuilder);
			return this;
		}

		/**
		 * Modifies the collection of {@link Saml2X509Credential} objects
		 * used in communication between IDP and SP
		 * For example:
		 * <code>
		 *     Saml2X509Credential credential = ...;
		 *     return RelyingPartyRegistration.withRegistrationId("id")
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
		 * <a href="https://wiki.shibboleth.net/confluence/display/CONCEPT/AssertionConsumerService">Assertion Consumer
		 * Service</a> URL template. It can contain variables {@code baseUrl}, {@code registrationId},
		 * {@code baseScheme}, {@code baseHost}, and {@code basePort}.
		 * @param assertionConsumerServiceUrlTemplate the Assertion Consumer Service URL template (i.e.
		 * "{baseUrl}/login/saml2/sso/{registrationId}".
		 * @return this object
		 * @deprecated Use {@link #assertionConsumerServiceLocation} instead.
		 */
		@Deprecated
		public Builder assertionConsumerServiceUrlTemplate(String assertionConsumerServiceUrlTemplate) {
			this.assertionConsumerServiceLocation = assertionConsumerServiceUrlTemplate;
			return this;
		}

		/**
		 * Sets the {@code entityId} for the remote asserting party, the Identity Provider.
		 * @param entityId the IDP entityId
		 * @return this object
		 * @deprecated use {@link #assertingPartyDetails(Consumer< AssertingPartyDetails.Builder >)}
		 */
		@Deprecated
		public Builder remoteIdpEntityId(String entityId) {
			assertingPartyDetails(idp -> idp.entityId(entityId));
			return this;
		}

		/**
		 * Sets the {@code SSO URL} for the remote asserting party, the Identity Provider.
		 * @param url - a URL that accepts authentication requests via REDIRECT or POST bindings
		 * @return this object
		 * @deprecated use {@link #assertingPartyDetails(Consumer< AssertingPartyDetails.Builder >)}
		 */
		@Deprecated
		public Builder idpWebSsoUrl(String url) {
			assertingPartyDetails(config -> config.singleSignOnServiceLocation(url));
			return this;
		}

		/**
		 * Sets the local relying party, or Service Provider, entity Id template.
		 * can generate it's entity ID based on possible variables of {@code baseUrl}, {@code registrationId},
		 * {@code baseScheme}, {@code baseHost}, and {@code basePort}, for example
		 * {@code {baseUrl}/saml2/service-provider-metadata/{registrationId}}
		 * @return a string containing the entity ID or entity ID template
		 * @deprecated Use {@link #entityId} instead
		 */
		@Deprecated
		public Builder localEntityIdTemplate(String template) {
			this.entityId = template;
			return this;
		}

		/**
		 * Configures the IDP SSO endpoint
		 * @param providerDetails a consumer that configures the IDP SSO endpoint
		 * @return this object
		 * @deprecated Use {@link #assertingPartyDetails} instead
		 */
		@Deprecated
		public Builder providerDetails(Consumer<ProviderDetails.Builder> providerDetails) {
			providerDetails.accept(this.providerDetails);
			return this;
		}

		/**
		 * Constructs a RelyingPartyRegistration object based on the builder configurations
		 * @return a RelyingPartyRegistration instance
		 */
		public RelyingPartyRegistration build() {
			return new RelyingPartyRegistration(
					this.registrationId,
					this.entityId,
					this.assertionConsumerServiceLocation,
					this.providerDetails.build(),
					this.credentials
			);
		}
	}

}
