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

package org.springframework.security.saml2.provider.service.web;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2ServletUtils;
import org.w3c.dom.Element;

import javax.servlet.http.HttpServletRequest;
import javax.xml.namespace.QName;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * @author Jakub Kubrynski
 * @since 5.4
 */
public class OpenSamlMetadataResolver implements Saml2MetadataResolver {

	@Override
	public String resolveMetadata(HttpServletRequest request, RelyingPartyRegistration registration) {

		XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();

		EntityDescriptor entityDescriptor = buildObject(builderFactory, EntityDescriptor.ELEMENT_QNAME);

		entityDescriptor.setEntityID(
				resolveTemplate(registration.getEntityId(), registration, request));

		SPSSODescriptor spSsoDescriptor = buildSpSsoDescriptor(registration, builderFactory, request);
		entityDescriptor.getRoleDescriptors(SPSSODescriptor.DEFAULT_ELEMENT_NAME).add(spSsoDescriptor);

		return serializeToXmlString(entityDescriptor);
	}

	private String serializeToXmlString(EntityDescriptor entityDescriptor) {
		Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(entityDescriptor);
		if (marshaller == null) {
			throw new Saml2Exception("Unable to resolve Marshaller");
		}
		Element element;
		try {
			element = marshaller.marshall(entityDescriptor);
		} catch (Exception e) {
			throw new Saml2Exception(e);
		}
		return SerializeSupport.prettyPrintXML(element);
	}

	private SPSSODescriptor buildSpSsoDescriptor(RelyingPartyRegistration registration,
			XMLObjectBuilderFactory builderFactory, HttpServletRequest request) {

		SPSSODescriptor spSsoDescriptor = buildObject(builderFactory, SPSSODescriptor.DEFAULT_ELEMENT_NAME);
		spSsoDescriptor.setAuthnRequestsSigned(registration.getAssertingPartyDetails().getWantAuthnRequestsSigned());
		spSsoDescriptor.setWantAssertionsSigned(true);
		spSsoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

		NameIDFormat nameIdFormat = buildObject(builderFactory, NameIDFormat.DEFAULT_ELEMENT_NAME);
		nameIdFormat.setFormat(registration.getAssertingPartyDetails().getNameIdFormat());
		spSsoDescriptor.getNameIDFormats().add(nameIdFormat);

		spSsoDescriptor.getAssertionConsumerServices().add(
				buildAssertionConsumerService(registration, builderFactory, request));

		spSsoDescriptor.getKeyDescriptors().addAll(buildKeys(builderFactory,
				registration.getSigningCredentials(), UsageType.SIGNING));
		spSsoDescriptor.getKeyDescriptors().addAll(buildKeys(builderFactory,
				registration.getEncryptionCredentials(), UsageType.ENCRYPTION));

		return spSsoDescriptor;
	}

	private List<KeyDescriptor> buildKeys(XMLObjectBuilderFactory builderFactory,
			List<Saml2X509Credential> credentials, UsageType usageType) {
		List<KeyDescriptor> list = new ArrayList<>();
		for (Saml2X509Credential credential : credentials) {
			KeyDescriptor keyDescriptor = buildKeyDescriptor(builderFactory, usageType, credential.getCertificate());
			list.add(keyDescriptor);
		}
		return list;
	}

	private KeyDescriptor buildKeyDescriptor(XMLObjectBuilderFactory builderFactory, UsageType usageType,
			java.security.cert.X509Certificate certificate) {
		KeyDescriptor keyDescriptor = buildObject(builderFactory, KeyDescriptor.DEFAULT_ELEMENT_NAME);
		KeyInfo keyInfo = buildObject(builderFactory, KeyInfo.DEFAULT_ELEMENT_NAME);
		X509Certificate x509Certificate = buildObject(builderFactory, X509Certificate.DEFAULT_ELEMENT_NAME);
		X509Data x509Data = buildObject(builderFactory, X509Data.DEFAULT_ELEMENT_NAME);

		try {
			x509Certificate.setValue(new String(Base64.getEncoder().encode(certificate.getEncoded())));
		} catch (CertificateEncodingException e) {
			throw new Saml2Exception("Cannot encode certificate " + certificate.toString());
		}

		x509Data.getX509Certificates().add(x509Certificate);
		keyInfo.getX509Datas().add(x509Data);

		keyDescriptor.setUse(usageType);
		keyDescriptor.setKeyInfo(keyInfo);
		return keyDescriptor;
	}

	private AssertionConsumerService buildAssertionConsumerService(RelyingPartyRegistration registration,
			XMLObjectBuilderFactory builderFactory, HttpServletRequest request) {
		AssertionConsumerService assertionConsumerService = buildObject(builderFactory, AssertionConsumerService.DEFAULT_ELEMENT_NAME);

		assertionConsumerService.setLocation(
				resolveTemplate(registration.getAssertionConsumerServiceLocation(), registration, request));
		assertionConsumerService.setBinding(registration.getAssertingPartyDetails().getSingleSignOnServiceBinding().getUrn());
		assertionConsumerService.setIndex(1);
		return assertionConsumerService;
	}

	@SuppressWarnings("unchecked")
	private <T> T buildObject(XMLObjectBuilderFactory builderFactory, QName elementName) {
		XMLObjectBuilder<?> builder = builderFactory.getBuilder(elementName);
		if (builder == null) {
			throw new Saml2Exception("Cannot build object - builder not defined for element " + elementName);
		}
		return (T) builder.buildObject(elementName);
	}

	private String resolveTemplate(String template, RelyingPartyRegistration registration, HttpServletRequest request) {
		return Saml2ServletUtils.resolveUrlTemplate(template, Saml2ServletUtils.getApplicationUri(request), registration);
	}

}
