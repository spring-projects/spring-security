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

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.Consumer;

import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.ext.saml2alg.SigningMethod;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.keyinfo.KeyInfoSupport;

import org.springframework.security.saml2.Saml2Exception;
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
		IDPSSODescriptor idpssoDescriptor = entity.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
		if (idpssoDescriptor == null) {
			throw new Saml2Exception("Metadata response is missing the necessary IDPSSODescriptor element");
		}
		List<Saml2X509Credential> verification = new ArrayList<>();
		List<Saml2X509Credential> encryption = new ArrayList<>();
		for (KeyDescriptor keyDescriptor : idpssoDescriptor.getKeyDescriptors()) {
			if (keyDescriptor.getUse().equals(UsageType.SIGNING)) {
				List<X509Certificate> certificates = certificates(keyDescriptor);
				for (X509Certificate certificate : certificates) {
					verification.add(Saml2X509Credential.verification(certificate));
				}
			}
			if (keyDescriptor.getUse().equals(UsageType.ENCRYPTION)) {
				List<X509Certificate> certificates = certificates(keyDescriptor);
				for (X509Certificate certificate : certificates) {
					encryption.add(Saml2X509Credential.encryption(certificate));
				}
			}
			if (keyDescriptor.getUse().equals(UsageType.UNSPECIFIED)) {
				List<X509Certificate> certificates = certificates(keyDescriptor);
				for (X509Certificate certificate : certificates) {
					verification.add(Saml2X509Credential.verification(certificate));
					encryption.add(Saml2X509Credential.encryption(certificate));
				}
			}
		}
		if (verification.isEmpty()) {
			throw new Saml2Exception(
					"Metadata response is missing verification certificates, necessary for verifying SAML assertions");
		}
		OpenSamlAssertingPartyDetails.Builder builder = new OpenSamlAssertingPartyDetails.Builder(entity)
			.entityId(entity.getEntityID())
			.wantAuthnRequestsSigned(Boolean.TRUE.equals(idpssoDescriptor.getWantAuthnRequestsSigned()))
			.verificationX509Credentials((c) -> c.addAll(verification))
			.encryptionX509Credentials((c) -> c.addAll(encryption));

		List<SigningMethod> signingMethods = signingMethods(idpssoDescriptor);
		for (SigningMethod method : signingMethods) {
			builder.signingAlgorithms((algorithms) -> algorithms.add(method.getAlgorithm()));
		}
		if (idpssoDescriptor.getSingleSignOnServices().isEmpty()) {
			throw new Saml2Exception(
					"Metadata response is missing a SingleSignOnService, necessary for sending AuthnRequests");
		}
		for (SingleSignOnService singleSignOnService : idpssoDescriptor.getSingleSignOnServices()) {
			Saml2MessageBinding binding;
			if (singleSignOnService.getBinding().equals(Saml2MessageBinding.POST.getUrn())) {
				binding = Saml2MessageBinding.POST;
			}
			else if (singleSignOnService.getBinding().equals(Saml2MessageBinding.REDIRECT.getUrn())) {
				binding = Saml2MessageBinding.REDIRECT;
			}
			else {
				continue;
			}
			builder.singleSignOnServiceLocation(singleSignOnService.getLocation()).singleSignOnServiceBinding(binding);
			break;
		}
		for (SingleLogoutService singleLogoutService : idpssoDescriptor.getSingleLogoutServices()) {
			Saml2MessageBinding binding;
			if (singleLogoutService.getBinding().equals(Saml2MessageBinding.POST.getUrn())) {
				binding = Saml2MessageBinding.POST;
			}
			else if (singleLogoutService.getBinding().equals(Saml2MessageBinding.REDIRECT.getUrn())) {
				binding = Saml2MessageBinding.REDIRECT;
			}
			else {
				continue;
			}
			String responseLocation = (singleLogoutService.getResponseLocation() == null)
					? singleLogoutService.getLocation() : singleLogoutService.getResponseLocation();
			builder.singleLogoutServiceLocation(singleLogoutService.getLocation())
				.singleLogoutServiceResponseLocation(responseLocation)
				.singleLogoutServiceBinding(binding);
			break;
		}
		return builder;
	}

	private static List<X509Certificate> certificates(KeyDescriptor keyDescriptor) {
		try {
			return KeyInfoSupport.getCertificates(keyDescriptor.getKeyInfo());
		}
		catch (CertificateException ex) {
			throw new Saml2Exception(ex);
		}
	}

	private static List<SigningMethod> signingMethods(IDPSSODescriptor idpssoDescriptor) {
		Extensions extensions = idpssoDescriptor.getExtensions();
		List<SigningMethod> result = signingMethods(extensions);
		if (!result.isEmpty()) {
			return result;
		}
		EntityDescriptor descriptor = (EntityDescriptor) idpssoDescriptor.getParent();
		extensions = descriptor.getExtensions();
		return signingMethods(extensions);
	}

	private static <T> List<T> signingMethods(Extensions extensions) {
		if (extensions != null) {
			return (List<T>) extensions.getUnknownXMLObjects(SigningMethod.DEFAULT_ELEMENT_NAME);
		}
		return new ArrayList<>();
	}

	@Override
	public OpenSamlAssertingPartyDetails.Builder mutate() {
		return new OpenSamlAssertingPartyDetails.Builder(this.descriptor).entityId(getEntityId())
			.wantAuthnRequestsSigned(getWantAuthnRequestsSigned())
			.signingAlgorithms((algorithms) -> algorithms.addAll(getSigningAlgorithms()))
			.verificationX509Credentials((c) -> c.addAll(getVerificationX509Credentials()))
			.encryptionX509Credentials((c) -> c.addAll(getEncryptionX509Credentials()))
			.singleSignOnServiceLocation(getSingleSignOnServiceLocation())
			.singleSignOnServiceBinding(getSingleSignOnServiceBinding())
			.singleLogoutServiceLocation(getSingleLogoutServiceLocation())
			.singleLogoutServiceResponseLocation(getSingleLogoutServiceResponseLocation())
			.singleLogoutServiceBinding(getSingleLogoutServiceBinding());
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
