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

import java.util.Collection;
import java.util.function.Consumer;

import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import org.springframework.security.saml2.core.Saml2X509Credential;

/**
 * An OpenSAML implementation of {@link RelyingPartyRegistration} that contains OpenSAML
 * objects like {@link EntityDescriptor}.
 *
 * @author Josh Cummings
 * @since 6.1
 * @deprecated This class no longer is needed in order to transmit the
 * {@link EntityDescriptor} to {@link OpenSamlAssertingPartyDetails}. Instead of doing:
 * <pre>
 * 	if (registration instanceof OpenSamlRelyingPartyRegistration openSamlRegistration) {
 * 	    EntityDescriptor descriptor = openSamlRegistration.getAssertingPartyDetails.getEntityDescriptor();
 * 	}
 * </pre> do instead: <pre>
 * 	if (registration.getAssertingPartyMetadata() instanceof openSamlAssertingPartyDetails) {
 * 	    EntityDescriptor descriptor = openSamlAssertingPartyDetails.getEntityDescriptor();
 * 	}
 * </pre>
 */
@Deprecated
public final class OpenSamlRelyingPartyRegistration extends RelyingPartyRegistration {

	OpenSamlRelyingPartyRegistration(RelyingPartyRegistration registration) {
		super(registration.getRegistrationId(), registration.getEntityId(),
				registration.getAssertionConsumerServiceLocation(), registration.getAssertionConsumerServiceBinding(),
				registration.getSingleLogoutServiceLocation(), registration.getSingleLogoutServiceResponseLocation(),
				registration.getSingleLogoutServiceBindings(), registration.getAssertingPartyDetails(),
				registration.getNameIdFormat(), registration.isAuthnRequestsSigned(),
				registration.getDecryptionX509Credentials(), registration.getSigningX509Credentials());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public OpenSamlRelyingPartyRegistration.Builder mutate() {
		OpenSamlAssertingPartyDetails party = getAssertingPartyDetails();
		return new Builder(party).registrationId(getRegistrationId())
			.entityId(getEntityId())
			.signingX509Credentials((c) -> c.addAll(getSigningX509Credentials()))
			.decryptionX509Credentials((c) -> c.addAll(getDecryptionX509Credentials()))
			.assertionConsumerServiceLocation(getAssertionConsumerServiceLocation())
			.assertionConsumerServiceBinding(getAssertionConsumerServiceBinding())
			.singleLogoutServiceLocation(getSingleLogoutServiceLocation())
			.singleLogoutServiceResponseLocation(getSingleLogoutServiceResponseLocation())
			.singleLogoutServiceBindings((c) -> c.addAll(getSingleLogoutServiceBindings()))
			.nameIdFormat(getNameIdFormat())
			.authnRequestsSigned(isAuthnRequestsSigned());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public OpenSamlAssertingPartyDetails getAssertingPartyDetails() {
		return (OpenSamlAssertingPartyDetails) super.getAssertingPartyDetails();
	}

	/**
	 * Create a {@link Builder} from an entity descriptor
	 * @param entityDescriptor the asserting party's {@link EntityDescriptor}
	 * @return an {@link Builder}
	 */
	public static OpenSamlRelyingPartyRegistration.Builder withAssertingPartyEntityDescriptor(
			EntityDescriptor entityDescriptor) {
		return new Builder(entityDescriptor);
	}

	/**
	 * An OpenSAML version of
	 * {@link org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration.AssertingPartyDetails.Builder}
	 * that contains the underlying {@link EntityDescriptor}
	 */
	public static final class Builder extends RelyingPartyRegistration.Builder {

		private Builder(EntityDescriptor entityDescriptor) {
			super(entityDescriptor.getEntityID(), OpenSamlAssertingPartyDetails.withEntityDescriptor(entityDescriptor));
		}

		Builder(OpenSamlAssertingPartyDetails details) {
			super(details.getEntityDescriptor().getEntityID(), details.mutate());
		}

		@Override
		public Builder registrationId(String id) {
			return (Builder) super.registrationId(id);
		}

		public Builder entityId(String entityId) {
			return (Builder) super.entityId(entityId);
		}

		public Builder signingX509Credentials(Consumer<Collection<Saml2X509Credential>> credentialsConsumer) {
			return (Builder) super.signingX509Credentials(credentialsConsumer);
		}

		@Override
		public Builder decryptionX509Credentials(Consumer<Collection<Saml2X509Credential>> credentialsConsumer) {
			return (Builder) super.decryptionX509Credentials(credentialsConsumer);
		}

		@Override
		public Builder assertionConsumerServiceLocation(String assertionConsumerServiceLocation) {
			return (Builder) super.assertionConsumerServiceLocation(assertionConsumerServiceLocation);
		}

		@Override
		public Builder assertionConsumerServiceBinding(Saml2MessageBinding assertionConsumerServiceBinding) {
			return (Builder) super.assertionConsumerServiceBinding(assertionConsumerServiceBinding);
		}

		@Override
		public Builder singleLogoutServiceBinding(Saml2MessageBinding singleLogoutServiceBinding) {
			return singleLogoutServiceBindings((saml2MessageBindings) -> {
				saml2MessageBindings.clear();
				saml2MessageBindings.add(singleLogoutServiceBinding);
			});
		}

		@Override
		public Builder singleLogoutServiceBindings(Consumer<Collection<Saml2MessageBinding>> bindingsConsumer) {
			return (Builder) super.singleLogoutServiceBindings(bindingsConsumer);
		}

		@Override
		public Builder singleLogoutServiceLocation(String singleLogoutServiceLocation) {
			return (Builder) super.singleLogoutServiceLocation(singleLogoutServiceLocation);
		}

		public Builder singleLogoutServiceResponseLocation(String singleLogoutServiceResponseLocation) {
			return (Builder) super.singleLogoutServiceResponseLocation(singleLogoutServiceResponseLocation);
		}

		@Override
		public Builder nameIdFormat(String nameIdFormat) {
			return (Builder) super.nameIdFormat(nameIdFormat);
		}

		@Override
		public Builder authnRequestsSigned(Boolean authnRequestsSigned) {
			return (Builder) super.authnRequestsSigned(authnRequestsSigned);
		}

		@Override
		public Builder assertingPartyDetails(Consumer<AssertingPartyDetails.Builder> assertingPartyDetails) {
			return (Builder) super.assertingPartyDetails(assertingPartyDetails);
		}

		@Override
		public Builder assertingPartyMetadata(Consumer<AssertingPartyMetadata.Builder<?>> assertingPartyMetadata) {
			return (Builder) super.assertingPartyMetadata(assertingPartyMetadata);
		}

		/**
		 * Build an {@link OpenSamlRelyingPartyRegistration}
		 * {@link org.springframework.security.saml2.provider.service.registration.OpenSamlRelyingPartyRegistration}
		 * @return an {@link OpenSamlRelyingPartyRegistration}
		 */
		@Override
		public OpenSamlRelyingPartyRegistration build() {
			return new OpenSamlRelyingPartyRegistration(super.build());
		}

	}

}
