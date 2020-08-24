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

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorUnmarshaller;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.keyinfo.KeyInfoSupport;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2X509Credential;

/**
 * An {@link HttpMessageConverter} that takes an {@code IDPSSODescriptor} in an HTTP
 * response and converts it into a {@link RelyingPartyRegistration.Builder}.
 *
 * The primary use case for this is constructing a {@link RelyingPartyRegistration} for
 * inclusion in a {@link RelyingPartyRegistrationRepository}. To do so, you can include an
 * instance of this converter in a {@link org.springframework.web.client.RestOperations}
 * like so:
 *
 * <pre>
 * 		RestOperations rest = new RestTemplate(Collections.singletonList(
 *     			new RelyingPartyRegistrationsBuilderHttpMessageConverter()));
 * 		RelyingPartyRegistration.Builder builder = rest.getForObject
 * 				("https://idp.example.org/metadata", RelyingPartyRegistration.Builder.class);
 * 		RelyingPartyRegistration registration = builder.registrationId("registration-id").build();
 * </pre>
 *
 * Note that this will only configure the asserting party (IDP) half of the
 * {@link RelyingPartyRegistration}, meaning where and how to send AuthnRequests, how to
 * verify Assertions, etc.
 *
 * To further configure the {@link RelyingPartyRegistration} with relying party (SP)
 * information, you may invoke the appropriate methods on the builder.
 *
 * @author Josh Cummings
 * @since 5.4
 */
public class OpenSamlRelyingPartyRegistrationBuilderHttpMessageConverter
		implements HttpMessageConverter<RelyingPartyRegistration.Builder> {

	static {
		OpenSamlInitializationService.initialize();
	}

	private final EntityDescriptorUnmarshaller unmarshaller;

	private final ParserPool parserPool;

	/**
	 * Creates a {@link OpenSamlRelyingPartyRegistrationBuilderHttpMessageConverter}
	 */
	public OpenSamlRelyingPartyRegistrationBuilderHttpMessageConverter() {
		XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		this.unmarshaller = (EntityDescriptorUnmarshaller) registry.getUnmarshallerFactory()
				.getUnmarshaller(EntityDescriptor.DEFAULT_ELEMENT_NAME);
		this.parserPool = registry.getParserPool();
	}

	@Override
	public boolean canRead(Class<?> clazz, MediaType mediaType) {
		return RelyingPartyRegistration.Builder.class.isAssignableFrom(clazz);
	}

	@Override
	public boolean canWrite(Class<?> clazz, MediaType mediaType) {
		return false;
	}

	@Override
	public List<MediaType> getSupportedMediaTypes() {
		return Arrays.asList(MediaType.APPLICATION_XML, MediaType.TEXT_XML);
	}

	@Override
	public RelyingPartyRegistration.Builder read(Class<? extends RelyingPartyRegistration.Builder> clazz,
			HttpInputMessage inputMessage) throws IOException, HttpMessageNotReadableException {
		EntityDescriptor descriptor = entityDescriptor(inputMessage.getBody());
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
		RelyingPartyRegistration.Builder builder = RelyingPartyRegistration.withRegistrationId(descriptor.getEntityID())
				.assertingPartyDetails((party) -> party.entityId(descriptor.getEntityID())
						.wantAuthnRequestsSigned(Boolean.TRUE.equals(idpssoDescriptor.getWantAuthnRequestsSigned()))
						.verificationX509Credentials((c) -> c.addAll(verification))
						.encryptionX509Credentials((c) -> c.addAll(encryption)));
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
			builder.assertingPartyDetails(
					(party) -> party.singleSignOnServiceLocation(singleSignOnService.getLocation())
							.singleSignOnServiceBinding(binding));
			return builder;
		}
		throw new Saml2Exception(
				"Metadata response is missing a SingleSignOnService, necessary for sending AuthnRequests");
	}

	private List<Saml2X509Credential> getVerification(IDPSSODescriptor idpssoDescriptor) {
		List<Saml2X509Credential> verification = new ArrayList<>();
		for (KeyDescriptor keyDescriptor : idpssoDescriptor.getKeyDescriptors()) {
			if (keyDescriptor.getUse().equals(UsageType.SIGNING)) {
				List<X509Certificate> certificates = certificates(keyDescriptor);
				for (X509Certificate certificate : certificates) {
					verification.add(Saml2X509Credential.verification(certificate));
				}
			}
		}
		return verification;
	}

	private List<Saml2X509Credential> getEncryption(IDPSSODescriptor idpssoDescriptor) {
		List<Saml2X509Credential> encryption = new ArrayList<>();
		for (KeyDescriptor keyDescriptor : idpssoDescriptor.getKeyDescriptors()) {
			if (keyDescriptor.getUse().equals(UsageType.ENCRYPTION)) {
				List<X509Certificate> certificates = certificates(keyDescriptor);
				for (X509Certificate certificate : certificates) {
					encryption.add(Saml2X509Credential.encryption(certificate));
				}
			}
		}
		return encryption;
	}

	private List<X509Certificate> certificates(KeyDescriptor keyDescriptor) {
		try {
			return KeyInfoSupport.getCertificates(keyDescriptor.getKeyInfo());
		}
		catch (CertificateException ex) {
			throw new Saml2Exception(ex);
		}
	}

	private EntityDescriptor entityDescriptor(InputStream inputStream) {
		try {
			Document document = this.parserPool.parse(inputStream);
			Element element = document.getDocumentElement();
			return (EntityDescriptor) this.unmarshaller.unmarshall(element);
		}
		catch (Exception ex) {
			throw new Saml2Exception(ex);
		}
	}

	@Override
	public void write(RelyingPartyRegistration.Builder builder, MediaType contentType, HttpOutputMessage outputMessage)
			throws HttpMessageNotWritableException {
		throw new HttpMessageNotWritableException("This converter cannot write a RelyingPartyRegistration.Builder");
	}

}
