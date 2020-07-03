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

package org.springframework.security.saml2.provider.service.registration;

import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.keyinfo.KeyInfoSupport;
import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.w3c.dom.Document;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.springframework.security.saml2.credentials.Saml2X509Credential.Saml2X509CredentialType.VERIFICATION;

/**
 * @since 5.4
 * @author Jakub Kubrynski
 */
public class SamlMetadataParser {

	private String assertionConsumerServiceUrlTemplate;

	public SamlMetadataParser(String assertionConsumerServiceUrlTemplate) {
		this.assertionConsumerServiceUrlTemplate = assertionConsumerServiceUrlTemplate;
	}

	public RelyingPartyRegistration parseIdentityProviderMetadata(String registrationId, String metadataXml)
			throws SamlMetadataParsingException {
		return parseIdentityProviderMetadata(registrationId, metadataXml, Collections.emptyList());
	}

	public RelyingPartyRegistration parseIdentityProviderMetadata(String registrationId, String metadataXml,
			Collection<Saml2X509Credential> serviceProviderCertificates) throws SamlMetadataParsingException {
		InputStream metadataInputStream = new ByteArrayInputStream(metadataXml.getBytes());

		XMLObjectProviderRegistry xmlObjectProviderRegistry = ConfigurationService.get(XMLObjectProviderRegistry.class);

		EntityDescriptor entityDescriptor = extractEntityDescriptor(metadataInputStream, xmlObjectProviderRegistry);

		String entityID = entityDescriptor.getEntityID();
		IDPSSODescriptor idpssoDescriptor = entityDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);

		SingleSignOnService singleSignOnService = idpssoDescriptor.getSingleSignOnServices().stream().findFirst()
				.orElseThrow(() -> new SamlMetadataParsingException("No SingleSignOnService found inside metadata"));

		List<Saml2X509Credential> signingCertificates = idpssoDescriptor.getKeyDescriptors().stream()
				.filter(keyDescriptor -> keyDescriptor.getUse() == UsageType.SIGNING)
				.flatMap(keyDescriptor -> extractCertificates(keyDescriptor).stream())
				.map(this::getVerificationCertificate)
				.collect(Collectors.toList());

		return RelyingPartyRegistration
				.withRegistrationId(registrationId)
				.providerDetails(builder -> builder.entityId(entityID)
						.webSsoUrl(singleSignOnService.getLocation())
						.binding(getBinding(singleSignOnService))
						.signAuthNRequest(idpssoDescriptor.getWantAuthnRequestsSigned()))
				.assertionConsumerServiceUrlTemplate(assertionConsumerServiceUrlTemplate)
				.credentials(c -> c.addAll(signingCertificates))
				.credentials(c -> c.addAll(serviceProviderCertificates))
				.build();
	}

	private List<X509Certificate> extractCertificates(KeyDescriptor keyDescriptor) {
		try {
			return KeyInfoSupport.getCertificates(keyDescriptor.getKeyInfo());
		} catch (CertificateException e) {
			throw new IllegalArgumentException(e);
		}
	}

	private Saml2MessageBinding getBinding(SingleSignOnService ssoService) {
		if (ssoService.getBinding().equals(Saml2MessageBinding.POST.getUrn())) {
			return Saml2MessageBinding.POST;
		} else {
			return Saml2MessageBinding.REDIRECT;
		}
	}

	private EntityDescriptor extractEntityDescriptor(InputStream metadataInputStream, XMLObjectProviderRegistry xmlObjectProviderRegistry) throws SamlMetadataParsingException {
		try {
			Document parse = xmlObjectProviderRegistry.getParserPool().parse(metadataInputStream);
			Unmarshaller unmarshaller = XMLObjectProviderRegistrySupport.getUnmarshallerFactory().getUnmarshaller(
					parse.getDocumentElement());

			if (unmarshaller == null) {
				throw new SamlMetadataParsingException("Cannot construct unmarshaller: null");
			}

			return (EntityDescriptor) unmarshaller.unmarshall(parse.getDocumentElement());
		} catch (XMLParserException | UnmarshallingException e) {
			throw new SamlMetadataParsingException(e);
		}
	}

	private Saml2X509Credential getVerificationCertificate(X509Certificate certificate) {
		return new Saml2X509Credential(certificate, VERIFICATION);
	}


}
