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

import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.ext.saml2alg.SigningMethod;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.keyinfo.KeyInfoSupport;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2X509Credential;

class OpenSamlMetadataAssertingPartyDetailsConverter {

	static {
		OpenSamlInitializationService.initialize();
	}

	private final XMLObjectProviderRegistry registry;

	private final ParserPool parserPool;

	/**
	 * Creates a {@link OpenSamlMetadataAssertingPartyDetailsConverter}
	 */
	OpenSamlMetadataAssertingPartyDetailsConverter() {
		this.registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		this.parserPool = this.registry.getParserPool();
	}

	Collection<RelyingPartyRegistration.AssertingPartyDetails.Builder> convert(InputStream inputStream) {
		List<RelyingPartyRegistration.AssertingPartyDetails.Builder> builders = new ArrayList<>();
		XMLObject xmlObject = xmlObject(inputStream);
		if (xmlObject instanceof EntitiesDescriptor) {
			EntitiesDescriptor descriptors = (EntitiesDescriptor) xmlObject;
			for (EntityDescriptor descriptor : descriptors.getEntityDescriptors()) {
				builders.add(convert(descriptor));
			}
			return builders;
		}
		if (xmlObject instanceof EntityDescriptor) {
			EntityDescriptor descriptor = (EntityDescriptor) xmlObject;
			return Arrays.asList(convert(descriptor));
		}
		throw new Saml2Exception("Unsupported element of type " + xmlObject.getClass());
	}

	RelyingPartyRegistration.AssertingPartyDetails.Builder convert(EntityDescriptor descriptor) {
		IDPSSODescriptor idpssoDescriptor = descriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
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
		RelyingPartyRegistration.AssertingPartyDetails.Builder party = OpenSamlAssertingPartyDetails
				.withEntityDescriptor(descriptor).entityId(descriptor.getEntityID())
				.wantAuthnRequestsSigned(Boolean.TRUE.equals(idpssoDescriptor.getWantAuthnRequestsSigned()))
				.verificationX509Credentials((c) -> c.addAll(verification))
				.encryptionX509Credentials((c) -> c.addAll(encryption));
		List<SigningMethod> signingMethods = signingMethods(idpssoDescriptor);
		for (SigningMethod method : signingMethods) {
			party.signingAlgorithms((algorithms) -> algorithms.add(method.getAlgorithm()));
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
			party.singleSignOnServiceLocation(singleSignOnService.getLocation()).singleSignOnServiceBinding(binding);
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
			party.singleLogoutServiceLocation(singleLogoutService.getLocation())
					.singleLogoutServiceResponseLocation(responseLocation).singleLogoutServiceBinding(binding);
			break;
		}
		return party;
	}

	private List<X509Certificate> certificates(KeyDescriptor keyDescriptor) {
		try {
			return KeyInfoSupport.getCertificates(keyDescriptor.getKeyInfo());
		}
		catch (CertificateException ex) {
			throw new Saml2Exception(ex);
		}
	}

	private List<SigningMethod> signingMethods(IDPSSODescriptor idpssoDescriptor) {
		Extensions extensions = idpssoDescriptor.getExtensions();
		List<SigningMethod> result = signingMethods(extensions);
		if (!result.isEmpty()) {
			return result;
		}
		EntityDescriptor descriptor = (EntityDescriptor) idpssoDescriptor.getParent();
		extensions = descriptor.getExtensions();
		return signingMethods(extensions);
	}

	private XMLObject xmlObject(InputStream inputStream) {
		Document document = document(inputStream);
		Element element = document.getDocumentElement();
		Unmarshaller unmarshaller = this.registry.getUnmarshallerFactory().getUnmarshaller(element);
		if (unmarshaller == null) {
			throw new Saml2Exception("Unsupported element of type " + element.getTagName());
		}
		try {
			return unmarshaller.unmarshall(element);
		}
		catch (Exception ex) {
			throw new Saml2Exception(ex);
		}
	}

	private Document document(InputStream inputStream) {
		try {
			return this.parserPool.parse(inputStream);
		}
		catch (Exception ex) {
			throw new Saml2Exception(ex);
		}
	}

	private <T> List<T> signingMethods(Extensions extensions) {
		if (extensions != null) {
			return (List<T>) extensions.getUnknownXMLObjects(SigningMethod.DEFAULT_ELEMENT_NAME);
		}
		return new ArrayList<>();
	}

}
