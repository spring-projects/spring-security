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

package org.springframework.security.saml2.provider.service.metadata;

import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.function.Consumer;

import javax.xml.namespace.QName;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorMarshaller;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.w3c.dom.Element;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.util.Assert;

/**
 * Resolves the SAML 2.0 Relying Party Metadata for a given
 * {@link RelyingPartyRegistration} using the OpenSAML API.
 *
 * @author Jakub Kubrynski
 * @author Josh Cummings
 * @since 5.4
 */
public final class OpenSamlMetadataResolver implements Saml2MetadataResolver {

	static {
		OpenSamlInitializationService.initialize();
	}

	private final EntityDescriptorMarshaller entityDescriptorMarshaller;

	private Consumer<EntityDescriptorParameters> entityDescriptorCustomizer = (parameters) -> {
	};

	public OpenSamlMetadataResolver() {
		this.entityDescriptorMarshaller = (EntityDescriptorMarshaller) XMLObjectProviderRegistrySupport
				.getMarshallerFactory().getMarshaller(EntityDescriptor.DEFAULT_ELEMENT_NAME);
		Assert.notNull(this.entityDescriptorMarshaller, "entityDescriptorMarshaller cannot be null");
	}

	@Override
	public String resolve(RelyingPartyRegistration relyingPartyRegistration) {
		EntityDescriptor entityDescriptor = build(EntityDescriptor.DEFAULT_ELEMENT_NAME);
		entityDescriptor.setEntityID(relyingPartyRegistration.getEntityId());
		SPSSODescriptor spSsoDescriptor = buildSpSsoDescriptor(relyingPartyRegistration);
		entityDescriptor.getRoleDescriptors(SPSSODescriptor.DEFAULT_ELEMENT_NAME).add(spSsoDescriptor);
		this.entityDescriptorCustomizer
				.accept(new EntityDescriptorParameters(entityDescriptor, relyingPartyRegistration));
		return serialize(entityDescriptor);
	}

	/**
	 * Set a {@link Consumer} for modifying the OpenSAML {@link EntityDescriptor}
	 * @param entityDescriptorCustomizer a consumer that accepts an
	 * {@link EntityDescriptorParameters}
	 * @since 5.7
	 */
	public void setEntityDescriptorCustomizer(Consumer<EntityDescriptorParameters> entityDescriptorCustomizer) {
		Assert.notNull(entityDescriptorCustomizer, "entityDescriptorCustomizer cannot be null");
		this.entityDescriptorCustomizer = entityDescriptorCustomizer;
	}

	private SPSSODescriptor buildSpSsoDescriptor(RelyingPartyRegistration registration) {
		SPSSODescriptor spSsoDescriptor = build(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
		spSsoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
		spSsoDescriptor.getKeyDescriptors()
				.addAll(buildKeys(registration.getSigningX509Credentials(), UsageType.SIGNING));
		spSsoDescriptor.getKeyDescriptors()
				.addAll(buildKeys(registration.getDecryptionX509Credentials(), UsageType.ENCRYPTION));
		spSsoDescriptor.getAssertionConsumerServices().add(buildAssertionConsumerService(registration));
		if (registration.getSingleLogoutServiceLocation() != null) {
			for (Saml2MessageBinding binding : registration.getSingleLogoutServiceBindings()) {
				spSsoDescriptor.getSingleLogoutServices().add(buildSingleLogoutService(registration, binding));
			}
		}
		if (registration.getNameIdFormat() != null) {
			spSsoDescriptor.getNameIDFormats().add(buildNameIDFormat(registration));
		}
		return spSsoDescriptor;
	}

	private List<KeyDescriptor> buildKeys(Collection<Saml2X509Credential> credentials, UsageType usageType) {
		List<KeyDescriptor> list = new ArrayList<>();
		for (Saml2X509Credential credential : credentials) {
			KeyDescriptor keyDescriptor = buildKeyDescriptor(usageType, credential.getCertificate());
			list.add(keyDescriptor);
		}
		return list;
	}

	private KeyDescriptor buildKeyDescriptor(UsageType usageType, java.security.cert.X509Certificate certificate) {
		KeyDescriptor keyDescriptor = build(KeyDescriptor.DEFAULT_ELEMENT_NAME);
		KeyInfo keyInfo = build(KeyInfo.DEFAULT_ELEMENT_NAME);
		X509Certificate x509Certificate = build(X509Certificate.DEFAULT_ELEMENT_NAME);
		X509Data x509Data = build(X509Data.DEFAULT_ELEMENT_NAME);
		try {
			x509Certificate.setValue(new String(Base64.getEncoder().encode(certificate.getEncoded())));
		}
		catch (CertificateEncodingException ex) {
			throw new Saml2Exception("Cannot encode certificate " + certificate.toString());
		}
		x509Data.getX509Certificates().add(x509Certificate);
		keyInfo.getX509Datas().add(x509Data);
		keyDescriptor.setUse(usageType);
		keyDescriptor.setKeyInfo(keyInfo);
		return keyDescriptor;
	}

	private AssertionConsumerService buildAssertionConsumerService(RelyingPartyRegistration registration) {
		AssertionConsumerService assertionConsumerService = build(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
		assertionConsumerService.setLocation(registration.getAssertionConsumerServiceLocation());
		assertionConsumerService.setBinding(registration.getAssertionConsumerServiceBinding().getUrn());
		assertionConsumerService.setIndex(1);
		return assertionConsumerService;
	}

	private SingleLogoutService buildSingleLogoutService(RelyingPartyRegistration registration,
			Saml2MessageBinding binding) {
		SingleLogoutService singleLogoutService = build(SingleLogoutService.DEFAULT_ELEMENT_NAME);
		singleLogoutService.setLocation(registration.getSingleLogoutServiceLocation());
		singleLogoutService.setResponseLocation(registration.getSingleLogoutServiceResponseLocation());
		singleLogoutService.setBinding(binding.getUrn());
		return singleLogoutService;
	}

	private NameIDFormat buildNameIDFormat(RelyingPartyRegistration registration) {
		NameIDFormat nameIdFormat = build(NameIDFormat.DEFAULT_ELEMENT_NAME);
		nameIdFormat.setFormat(registration.getNameIdFormat());
		return nameIdFormat;
	}

	@SuppressWarnings("unchecked")
	private <T> T build(QName elementName) {
		XMLObjectBuilder<?> builder = XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(elementName);
		if (builder == null) {
			throw new Saml2Exception("Unable to resolve Builder for " + elementName);
		}
		return (T) builder.buildObject(elementName);
	}

	private String serialize(EntityDescriptor entityDescriptor) {
		try {
			Element element = this.entityDescriptorMarshaller.marshall(entityDescriptor);
			return SerializeSupport.prettyPrintXML(element);
		}
		catch (Exception ex) {
			throw new Saml2Exception(ex);
		}
	}

	/**
	 * A tuple containing an OpenSAML {@link EntityDescriptor} and its associated
	 * {@link RelyingPartyRegistration}
	 *
	 * @since 5.7
	 */
	public static final class EntityDescriptorParameters {

		private final EntityDescriptor entityDescriptor;

		private final RelyingPartyRegistration registration;

		public EntityDescriptorParameters(EntityDescriptor entityDescriptor, RelyingPartyRegistration registration) {
			this.entityDescriptor = entityDescriptor;
			this.registration = registration;
		}

		public EntityDescriptor getEntityDescriptor() {
			return this.entityDescriptor;
		}

		public RelyingPartyRegistration getRelyingPartyRegistration() {
			return this.registration;
		}

	}

}
