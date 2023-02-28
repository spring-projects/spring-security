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
import java.util.List;
import java.util.function.Consumer;

import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import org.springframework.security.saml2.core.Saml2X509Credential;

/**
 * A {@link RelyingPartyRegistration.AssertingPartyDetails} that contains
 * OpenSAML-specific members
 *
 * @author Josh Cummings
 * @since 5.7
 */
public final class OpenSamlAssertingPartyDetails extends RelyingPartyRegistration.AssertingPartyDetails {

	private final EntityDescriptor descriptor;

	OpenSamlAssertingPartyDetails(RelyingPartyRegistration.AssertingPartyDetails details, EntityDescriptor descriptor) {
		super(details.getEntityId(), details.getWantAuthnRequestsSigned(), details.getSigningAlgorithms(),
				details.getVerificationX509Credentials(), details.getEncryptionX509Credentials(),
				details.getSingleSignOnServiceLocation(), details.getSingleSignOnServiceBinding(),
				details.getSingleLogoutServiceLocation(), details.getSingleLogoutServiceResponseLocation(),
				details.getSingleLogoutServiceBinding());
		this.descriptor = descriptor;
	}

	/**
	 * Get the {@link EntityDescriptor} that underlies this
	 * {@link org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration.AssertingPartyDetails}
	 * @return the {@link EntityDescriptor}
	 */
	public EntityDescriptor getEntityDescriptor() {
		return this.descriptor;
	}

	/**
	 * Use this {@link EntityDescriptor} to begin building an
	 * {@link org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration.AssertingPartyDetails}
	 * @param entity the {@link EntityDescriptor} to use
	 * @return the
	 * {@link org.springframework.security.saml2.provider.service.registration.OpenSamlAssertingPartyDetails.Builder}
	 * for further configurations
	 */
	public static OpenSamlAssertingPartyDetails.Builder withEntityDescriptor(EntityDescriptor entity) {
		return new OpenSamlAssertingPartyDetails.Builder(entity);
	}

	/**
	 * An OpenSAML version of
	 * {@link org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration.AssertingPartyDetails.Builder}
	 * that contains the underlying {@link EntityDescriptor}
	 */
	public static final class Builder extends RelyingPartyRegistration.AssertingPartyDetails.Builder {

		private EntityDescriptor descriptor;

		private Builder(EntityDescriptor descriptor) {
			this.descriptor = descriptor;
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public Builder entityId(String entityId) {
			return (Builder) super.entityId(entityId);
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public Builder wantAuthnRequestsSigned(boolean wantAuthnRequestsSigned) {
			return (Builder) super.wantAuthnRequestsSigned(wantAuthnRequestsSigned);
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public Builder signingAlgorithms(Consumer<List<String>> signingMethodAlgorithmsConsumer) {
			return (Builder) super.signingAlgorithms(signingMethodAlgorithmsConsumer);
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public Builder verificationX509Credentials(Consumer<Collection<Saml2X509Credential>> credentialsConsumer) {
			return (Builder) super.verificationX509Credentials(credentialsConsumer);
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public Builder encryptionX509Credentials(Consumer<Collection<Saml2X509Credential>> credentialsConsumer) {
			return (Builder) super.encryptionX509Credentials(credentialsConsumer);
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public Builder singleSignOnServiceLocation(String singleSignOnServiceLocation) {
			return (Builder) super.singleSignOnServiceLocation(singleSignOnServiceLocation);
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public Builder singleSignOnServiceBinding(Saml2MessageBinding singleSignOnServiceBinding) {
			return (Builder) super.singleSignOnServiceBinding(singleSignOnServiceBinding);
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public Builder singleLogoutServiceLocation(String singleLogoutServiceLocation) {
			return (Builder) super.singleLogoutServiceLocation(singleLogoutServiceLocation);
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public Builder singleLogoutServiceResponseLocation(String singleLogoutServiceResponseLocation) {
			return (Builder) super.singleLogoutServiceResponseLocation(singleLogoutServiceResponseLocation);
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public Builder singleLogoutServiceBinding(Saml2MessageBinding singleLogoutServiceBinding) {
			return (Builder) super.singleLogoutServiceBinding(singleLogoutServiceBinding);
		}

		/**
		 * Build an
		 * {@link org.springframework.security.saml2.provider.service.registration.OpenSamlAssertingPartyDetails}
		 * @return
		 */
		@Override
		public OpenSamlAssertingPartyDetails build() {
			return new OpenSamlAssertingPartyDetails(super.build(), this.descriptor);
		}

	}

}
