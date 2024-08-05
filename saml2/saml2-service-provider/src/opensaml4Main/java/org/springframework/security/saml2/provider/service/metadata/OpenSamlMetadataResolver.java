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

package org.springframework.security.saml2.provider.service.metadata;

import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.function.Consumer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;

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
 * @deprecated Please use version-specific {@link Saml2MetadataResolver} instead, for
 * example {@code OpenSaml4MetadataResolver}
 */
@Deprecated
public final class OpenSamlMetadataResolver implements Saml2MetadataResolver {

	static {
		OpenSamlInitializationService.initialize();
	}

	private final Log logger = LogFactory.getLog(this.getClass());

	private OpenSamlOperations saml = new OpenSaml4Template();

	private Consumer<EntityDescriptorParameters> entityDescriptorCustomizer = (parameters) -> {
	};

	private boolean usePrettyPrint = true;

	private boolean signMetadata = false;

	public OpenSamlMetadataResolver() {
	}

	OpenSamlMetadataResolver(OpenSamlOperations saml) {
		this.saml = saml;
	}

	@Override
	public String resolve(RelyingPartyRegistration relyingPartyRegistration) {
		EntityDescriptor entityDescriptor = entityDescriptor(relyingPartyRegistration);
		return serialize(entityDescriptor);
	}

	public String resolve(Iterable<RelyingPartyRegistration> relyingPartyRegistrations) {
		Collection<EntityDescriptor> entityDescriptors = new ArrayList<>();
		for (RelyingPartyRegistration registration : relyingPartyRegistrations) {
			EntityDescriptor entityDescriptor = entityDescriptor(registration);
			entityDescriptors.add(entityDescriptor);
		}
		if (entityDescriptors.size() == 1) {
			return serialize(entityDescriptors.iterator().next());
		}
		EntitiesDescriptor entities = this.saml.build(EntitiesDescriptor.DEFAULT_ELEMENT_NAME);
		entities.getEntityDescriptors().addAll(entityDescriptors);
		return serialize(entities);
	}

	private EntityDescriptor entityDescriptor(RelyingPartyRegistration registration) {
		EntityDescriptor entityDescriptor = this.saml.build(EntityDescriptor.DEFAULT_ELEMENT_NAME);
		entityDescriptor.setEntityID(registration.getEntityId());
		SPSSODescriptor spSsoDescriptor = buildSpSsoDescriptor(registration);
		entityDescriptor.getRoleDescriptors(SPSSODescriptor.DEFAULT_ELEMENT_NAME).add(spSsoDescriptor);
		this.entityDescriptorCustomizer.accept(new EntityDescriptorParameters(entityDescriptor, registration));
		if (this.signMetadata) {
			return this.saml.withSigningKeys(registration.getSigningX509Credentials())
				.algorithms(registration.getAssertingPartyMetadata().getSigningAlgorithms())
				.sign(entityDescriptor);
		}
		else {
			this.logger.trace("Did not sign metadata since `signMetadata` is `false`");
		}
		return entityDescriptor;
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

	/**
	 * Configure whether to pretty-print the metadata XML. This can be helpful when
	 * signing the metadata payload.
	 *
	 * @since 6.2
	 **/
	public void setUsePrettyPrint(boolean usePrettyPrint) {
		this.usePrettyPrint = usePrettyPrint;
	}

	private SPSSODescriptor buildSpSsoDescriptor(RelyingPartyRegistration registration) {
		SPSSODescriptor spSsoDescriptor = this.saml.build(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
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
		KeyDescriptor keyDescriptor = this.saml.build(KeyDescriptor.DEFAULT_ELEMENT_NAME);
		KeyInfo keyInfo = this.saml.build(KeyInfo.DEFAULT_ELEMENT_NAME);
		X509Certificate x509Certificate = this.saml.build(X509Certificate.DEFAULT_ELEMENT_NAME);
		X509Data x509Data = this.saml.build(X509Data.DEFAULT_ELEMENT_NAME);
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
		AssertionConsumerService assertionConsumerService = this.saml
			.build(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
		assertionConsumerService.setLocation(registration.getAssertionConsumerServiceLocation());
		assertionConsumerService.setBinding(registration.getAssertionConsumerServiceBinding().getUrn());
		assertionConsumerService.setIndex(1);
		return assertionConsumerService;
	}

	private SingleLogoutService buildSingleLogoutService(RelyingPartyRegistration registration,
			Saml2MessageBinding binding) {
		SingleLogoutService singleLogoutService = this.saml.build(SingleLogoutService.DEFAULT_ELEMENT_NAME);
		singleLogoutService.setLocation(registration.getSingleLogoutServiceLocation());
		singleLogoutService.setResponseLocation(registration.getSingleLogoutServiceResponseLocation());
		singleLogoutService.setBinding(binding.getUrn());
		return singleLogoutService;
	}

	private NameIDFormat buildNameIDFormat(RelyingPartyRegistration registration) {
		NameIDFormat nameIdFormat = this.saml.build(NameIDFormat.DEFAULT_ELEMENT_NAME);
		nameIdFormat.setURI(registration.getNameIdFormat());
		return nameIdFormat;
	}

	private String serialize(EntityDescriptor entityDescriptor) {
		return this.saml.serialize(entityDescriptor).prettyPrint(this.usePrettyPrint).serialize();
	}

	private String serialize(EntitiesDescriptor entities) {
		return this.saml.serialize(entities).prettyPrint(this.usePrettyPrint).serialize();
	}

	/**
	 * Configure whether to sign the metadata, defaults to {@code false}.
	 *
	 * @since 6.4
	 */
	public void setSignMetadata(boolean signMetadata) {
		this.signMetadata = signMetadata;
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
