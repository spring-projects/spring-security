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

package org.springframework.security.config.saml2;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.w3c.dom.Element;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.parsing.CompositeComponentDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;

/**
 * @author Marcus da Coregio
 * @since 5.7
 */
public final class RelyingPartyRegistrationsBeanDefinitionParser implements BeanDefinitionParser {

	private static final String ELT_RELYING_PARTY_REGISTRATION = "relying-party-registration";

	private static final String ELT_SIGNING_CREDENTIAL = "signing-credential";

	private static final String ELT_DECRYPTION_CREDENTIAL = "decryption-credential";

	private static final String ELT_ASSERTING_PARTY = "asserting-party";

	private static final String ELT_VERIFICATION_CREDENTIAL = "verification-credential";

	private static final String ELT_ENCRYPTION_CREDENTIAL = "encryption-credential";

	private static final String ATT_REGISTRATION_ID = "registration-id";

	private static final String ATT_ASSERTING_PARTY_ID = "asserting-party-id";

	private static final String ATT_ENTITY_ID = "entity-id";

	private static final String ATT_METADATA_LOCATION = "metadata-location";

	private static final String ATT_ASSERTION_CONSUMER_SERVICE_LOCATION = "assertion-consumer-service-location";

	private static final String ATT_ASSERTION_CONSUMER_SERVICE_BINDING = "assertion-consumer-service-binding";

	private static final String ATT_PRIVATE_KEY_LOCATION = "private-key-location";

	private static final String ATT_CERTIFICATE_LOCATION = "certificate-location";

	private static final String ATT_WANT_AUTHN_REQUESTS_SIGNED = "want-authn-requests-signed";

	private static final String ATT_SINGLE_SIGN_ON_SERVICE_LOCATION = "single-sign-on-service-location";

	private static final String ATT_SINGLE_SIGN_ON_SERVICE_BINDING = "single-sign-on-service-binding";

	private static final String ATT_SIGNING_ALGORITHMS = "signing-algorithms";

	private static final String ATT_SINGLE_LOGOUT_SERVICE_LOCATION = "single-logout-service-location";

	private static final String ATT_SINGLE_LOGOUT_SERVICE_RESPONSE_LOCATION = "single-logout-service-response-location";

	private static final String ATT_SINGLE_LOGOUT_SERVICE_BINDING = "single-logout-service-binding";

	private static final ResourceLoader resourceLoader = new DefaultResourceLoader();

	@Override
	public BeanDefinition parse(Element element, ParserContext parserContext) {
		CompositeComponentDefinition compositeDef = new CompositeComponentDefinition(element.getTagName(),
				parserContext.extractSource(element));
		parserContext.pushContainingComponent(compositeDef);
		Map<String, Map<String, Object>> assertingParties = getAssertingParties(element);
		List<RelyingPartyRegistration> relyingPartyRegistrations = getRelyingPartyRegistrations(element,
				assertingParties, parserContext);
		BeanDefinition relyingPartyRegistrationRepositoryBean = BeanDefinitionBuilder
				.rootBeanDefinition(InMemoryRelyingPartyRegistrationRepository.class)
				.addConstructorArgValue(relyingPartyRegistrations).getBeanDefinition();
		String relyingPartyRegistrationRepositoryId = parserContext.getReaderContext()
				.generateBeanName(relyingPartyRegistrationRepositoryBean);
		parserContext.registerBeanComponent(new BeanComponentDefinition(relyingPartyRegistrationRepositoryBean,
				relyingPartyRegistrationRepositoryId));
		parserContext.popAndRegisterContainingComponent();
		return null;
	}

	private static Map<String, Map<String, Object>> getAssertingParties(Element element) {
		List<Element> assertingPartyElts = DomUtils.getChildElementsByTagName(element, ELT_ASSERTING_PARTY);
		Map<String, Map<String, Object>> providers = new HashMap<>();
		for (Element assertingPartyElt : assertingPartyElts) {
			Map<String, Object> assertingParty = new HashMap<>();
			String assertingPartyId = assertingPartyElt.getAttribute(ATT_ASSERTING_PARTY_ID);
			String entityId = assertingPartyElt.getAttribute(ATT_ENTITY_ID);
			String wantAuthnRequestsSigned = assertingPartyElt.getAttribute(ATT_WANT_AUTHN_REQUESTS_SIGNED);
			String singleSignOnServiceLocation = assertingPartyElt.getAttribute(ATT_SINGLE_SIGN_ON_SERVICE_LOCATION);
			String singleSignOnServiceBinding = assertingPartyElt.getAttribute(ATT_SINGLE_SIGN_ON_SERVICE_BINDING);
			String signingAlgorithms = assertingPartyElt.getAttribute(ATT_SIGNING_ALGORITHMS);
			String singleLogoutServiceLocation = assertingPartyElt.getAttribute(ATT_SINGLE_LOGOUT_SERVICE_LOCATION);
			String singleLogoutServiceResponseLocation = assertingPartyElt
					.getAttribute(ATT_SINGLE_LOGOUT_SERVICE_RESPONSE_LOCATION);
			String singleLogoutServiceBinding = assertingPartyElt.getAttribute(ATT_SINGLE_LOGOUT_SERVICE_BINDING);
			assertingParty.put(ATT_ASSERTING_PARTY_ID, assertingPartyId);
			assertingParty.put(ATT_ENTITY_ID, entityId);
			assertingParty.put(ATT_WANT_AUTHN_REQUESTS_SIGNED, wantAuthnRequestsSigned);
			assertingParty.put(ATT_SINGLE_SIGN_ON_SERVICE_LOCATION, singleSignOnServiceLocation);
			assertingParty.put(ATT_SINGLE_SIGN_ON_SERVICE_BINDING, singleSignOnServiceBinding);
			assertingParty.put(ATT_SIGNING_ALGORITHMS, signingAlgorithms);
			assertingParty.put(ATT_SINGLE_LOGOUT_SERVICE_LOCATION, singleLogoutServiceLocation);
			assertingParty.put(ATT_SINGLE_LOGOUT_SERVICE_RESPONSE_LOCATION, singleLogoutServiceResponseLocation);
			assertingParty.put(ATT_SINGLE_LOGOUT_SERVICE_BINDING, singleLogoutServiceBinding);
			addVerificationCredentials(assertingPartyElt, assertingParty);
			addEncryptionCredentials(assertingPartyElt, assertingParty);
			providers.put(assertingPartyId, assertingParty);
		}
		return providers;
	}

	private static void addVerificationCredentials(Map<String, Object> assertingParty,
			RelyingPartyRegistration.AssertingPartyDetails.Builder builder) {
		List<String> verificationCertificateLocations = (List<String>) assertingParty.get(ELT_VERIFICATION_CREDENTIAL);
		List<Saml2X509Credential> verificationCredentials = new ArrayList<>();
		for (String certificateLocation : verificationCertificateLocations) {
			verificationCredentials.add(getSaml2VerificationCredential(certificateLocation));
		}
		builder.verificationX509Credentials((credentials) -> credentials.addAll(verificationCredentials));
	}

	private static void addEncryptionCredentials(Map<String, Object> assertingParty,
			RelyingPartyRegistration.AssertingPartyDetails.Builder builder) {
		List<String> encryptionCertificateLocations = (List<String>) assertingParty.get(ELT_ENCRYPTION_CREDENTIAL);
		List<Saml2X509Credential> encryptionCredentials = new ArrayList<>();
		for (String certificateLocation : encryptionCertificateLocations) {
			encryptionCredentials.add(getSaml2EncryptionCredential(certificateLocation));
		}
		builder.encryptionX509Credentials((credentials) -> credentials.addAll(encryptionCredentials));
	}

	private static void addVerificationCredentials(Element assertingPartyElt, Map<String, Object> assertingParty) {
		List<String> verificationCertificateLocations = new ArrayList<>();
		List<Element> verificationCredentialElts = DomUtils.getChildElementsByTagName(assertingPartyElt,
				ELT_VERIFICATION_CREDENTIAL);
		for (Element verificationCredentialElt : verificationCredentialElts) {
			String certificateLocation = verificationCredentialElt.getAttribute(ATT_CERTIFICATE_LOCATION);
			verificationCertificateLocations.add(certificateLocation);
		}
		assertingParty.put(ELT_VERIFICATION_CREDENTIAL, verificationCertificateLocations);
	}

	private static void addEncryptionCredentials(Element assertingPartyElt, Map<String, Object> assertingParty) {
		List<String> encryptionCertificateLocations = new ArrayList<>();
		List<Element> encryptionCredentialElts = DomUtils.getChildElementsByTagName(assertingPartyElt,
				ELT_VERIFICATION_CREDENTIAL);
		for (Element encryptionCredentialElt : encryptionCredentialElts) {
			String certificateLocation = encryptionCredentialElt.getAttribute(ATT_CERTIFICATE_LOCATION);
			encryptionCertificateLocations.add(certificateLocation);
		}
		assertingParty.put(ELT_ENCRYPTION_CREDENTIAL, encryptionCertificateLocations);
	}

	private List<RelyingPartyRegistration> getRelyingPartyRegistrations(Element element,
			Map<String, Map<String, Object>> assertingParties, ParserContext parserContext) {
		List<Element> relyingPartyRegistrationElts = DomUtils.getChildElementsByTagName(element,
				ELT_RELYING_PARTY_REGISTRATION);
		List<RelyingPartyRegistration> relyingPartyRegistrations = new ArrayList<>();
		for (Element relyingPartyRegistrationElt : relyingPartyRegistrationElts) {
			RelyingPartyRegistration.Builder builder = getBuilderFromMetadataLocationIfPossible(
					relyingPartyRegistrationElt, assertingParties, parserContext);
			addSigningCredentials(relyingPartyRegistrationElt, builder);
			addDecryptionCredentials(relyingPartyRegistrationElt, builder);
			relyingPartyRegistrations.add(builder.build());
		}
		return relyingPartyRegistrations;
	}

	private static RelyingPartyRegistration.Builder getBuilderFromMetadataLocationIfPossible(
			Element relyingPartyRegistrationElt, Map<String, Map<String, Object>> assertingParties,
			ParserContext parserContext) {
		String registrationId = relyingPartyRegistrationElt.getAttribute(ATT_REGISTRATION_ID);
		String metadataLocation = relyingPartyRegistrationElt.getAttribute(ATT_METADATA_LOCATION);
		String singleLogoutServiceLocation = relyingPartyRegistrationElt
				.getAttribute(ATT_SINGLE_LOGOUT_SERVICE_LOCATION);
		String singleLogoutServiceResponseLocation = relyingPartyRegistrationElt
				.getAttribute(ATT_SINGLE_LOGOUT_SERVICE_RESPONSE_LOCATION);
		Saml2MessageBinding singleLogoutServiceBinding = getSingleLogoutServiceBinding(relyingPartyRegistrationElt);
		if (StringUtils.hasText(metadataLocation)) {
			return RelyingPartyRegistrations.fromMetadataLocation(metadataLocation).registrationId(registrationId)
					.singleLogoutServiceLocation(singleLogoutServiceLocation)
					.singleLogoutServiceResponseLocation(singleLogoutServiceResponseLocation)
					.singleLogoutServiceBinding(singleLogoutServiceBinding);
		}
		String entityId = relyingPartyRegistrationElt.getAttribute(ATT_ENTITY_ID);
		String assertionConsumerServiceLocation = relyingPartyRegistrationElt
				.getAttribute(ATT_ASSERTION_CONSUMER_SERVICE_LOCATION);
		Saml2MessageBinding assertionConsumerServiceBinding = getAssertionConsumerServiceBinding(
				relyingPartyRegistrationElt);
		return RelyingPartyRegistration.withRegistrationId(registrationId).entityId(entityId)
				.assertionConsumerServiceLocation(assertionConsumerServiceLocation)
				.assertionConsumerServiceBinding(assertionConsumerServiceBinding)
				.singleLogoutServiceLocation(singleLogoutServiceLocation)
				.singleLogoutServiceResponseLocation(singleLogoutServiceResponseLocation)
				.singleLogoutServiceBinding(singleLogoutServiceBinding)
				.assertingPartyDetails((builder) -> buildAssertingParty(relyingPartyRegistrationElt, assertingParties,
						builder, parserContext));
	}

	private static void buildAssertingParty(Element relyingPartyElt, Map<String, Map<String, Object>> assertingParties,
			RelyingPartyRegistration.AssertingPartyDetails.Builder builder, ParserContext parserContext) {
		String assertingPartyId = relyingPartyElt.getAttribute(ATT_ASSERTING_PARTY_ID);
		if (!assertingParties.containsKey(assertingPartyId)) {
			Object source = parserContext.extractSource(relyingPartyElt);
			parserContext.getReaderContext()
					.error(String.format("Could not find asserting party with id %s", assertingPartyId), source);
		}
		Map<String, Object> assertingParty = assertingParties.get(assertingPartyId);
		String entityId = getAsString(assertingParty, ATT_ENTITY_ID);
		String wantAuthnRequestsSigned = getAsString(assertingParty, ATT_WANT_AUTHN_REQUESTS_SIGNED);
		String singleSignOnServiceLocation = getAsString(assertingParty, ATT_SINGLE_SIGN_ON_SERVICE_LOCATION);
		String singleSignOnServiceBinding = getAsString(assertingParty, ATT_SINGLE_SIGN_ON_SERVICE_BINDING);
		Saml2MessageBinding saml2MessageBinding = StringUtils.hasText(singleSignOnServiceBinding)
				? Saml2MessageBinding.valueOf(singleSignOnServiceBinding) : Saml2MessageBinding.REDIRECT;
		String singleLogoutServiceLocation = getAsString(assertingParty, ATT_SINGLE_LOGOUT_SERVICE_LOCATION);
		String singleLogoutServiceResponseLocation = getAsString(assertingParty,
				ATT_SINGLE_LOGOUT_SERVICE_RESPONSE_LOCATION);
		String singleLogoutServiceBinding = getAsString(assertingParty, ATT_SINGLE_LOGOUT_SERVICE_BINDING);
		Saml2MessageBinding saml2LogoutMessageBinding = StringUtils.hasText(singleLogoutServiceBinding)
				? Saml2MessageBinding.valueOf(singleLogoutServiceBinding) : Saml2MessageBinding.REDIRECT;
		builder.entityId(entityId).wantAuthnRequestsSigned(Boolean.parseBoolean(wantAuthnRequestsSigned))
				.singleSignOnServiceLocation(singleSignOnServiceLocation)
				.singleSignOnServiceBinding(saml2MessageBinding)
				.singleLogoutServiceLocation(singleLogoutServiceLocation)
				.singleLogoutServiceResponseLocation(singleLogoutServiceResponseLocation)
				.singleLogoutServiceBinding(saml2LogoutMessageBinding);
		addSigningAlgorithms(assertingParty, builder);
		addVerificationCredentials(assertingParty, builder);
		addEncryptionCredentials(assertingParty, builder);
	}

	private static void addSigningAlgorithms(Map<String, Object> assertingParty,
			RelyingPartyRegistration.AssertingPartyDetails.Builder builder) {
		String signingAlgorithmsAttr = getAsString(assertingParty, ATT_SIGNING_ALGORITHMS);
		if (StringUtils.hasText(signingAlgorithmsAttr)) {
			List<String> signingAlgorithms = Arrays.asList(signingAlgorithmsAttr.split(","));
			builder.signingAlgorithms((s) -> s.addAll(signingAlgorithms));
		}
	}

	private static void addSigningCredentials(Element relyingPartyRegistrationElt,
			RelyingPartyRegistration.Builder builder) {
		List<Element> credentialElts = DomUtils.getChildElementsByTagName(relyingPartyRegistrationElt,
				ELT_SIGNING_CREDENTIAL);
		for (Element credentialElt : credentialElts) {
			String privateKeyLocation = credentialElt.getAttribute(ATT_PRIVATE_KEY_LOCATION);
			String certificateLocation = credentialElt.getAttribute(ATT_CERTIFICATE_LOCATION);
			builder.signingX509Credentials(
					(c) -> c.add(getSaml2SigningCredential(privateKeyLocation, certificateLocation)));
		}
	}

	private static void addDecryptionCredentials(Element relyingPartyRegistrationElt,
			RelyingPartyRegistration.Builder builder) {
		List<Element> credentialElts = DomUtils.getChildElementsByTagName(relyingPartyRegistrationElt,
				ELT_DECRYPTION_CREDENTIAL);
		for (Element credentialElt : credentialElts) {
			String privateKeyLocation = credentialElt.getAttribute(ATT_PRIVATE_KEY_LOCATION);
			String certificateLocation = credentialElt.getAttribute(ATT_CERTIFICATE_LOCATION);
			Saml2X509Credential credential = getSaml2DecryptionCredential(privateKeyLocation, certificateLocation);
			builder.decryptionX509Credentials((c) -> c.add(credential));
		}
	}

	private static String getAsString(Map<String, Object> assertingParty, String key) {
		return (String) assertingParty.get(key);
	}

	private static Saml2MessageBinding getAssertionConsumerServiceBinding(Element relyingPartyRegistrationElt) {
		String assertionConsumerServiceBinding = relyingPartyRegistrationElt
				.getAttribute(ATT_ASSERTION_CONSUMER_SERVICE_BINDING);
		if (StringUtils.hasText(assertionConsumerServiceBinding)) {
			return Saml2MessageBinding.valueOf(assertionConsumerServiceBinding);
		}
		return Saml2MessageBinding.REDIRECT;
	}

	private static Saml2MessageBinding getSingleLogoutServiceBinding(Element relyingPartyRegistrationElt) {
		String singleLogoutServiceBinding = relyingPartyRegistrationElt.getAttribute(ATT_SINGLE_LOGOUT_SERVICE_BINDING);
		if (StringUtils.hasText(singleLogoutServiceBinding)) {
			return Saml2MessageBinding.valueOf(singleLogoutServiceBinding);
		}
		return Saml2MessageBinding.POST;
	}

	private static Saml2X509Credential getSaml2VerificationCredential(String certificateLocation) {
		return getSaml2Credential(certificateLocation, Saml2X509Credential.Saml2X509CredentialType.VERIFICATION);
	}

	private static Saml2X509Credential getSaml2EncryptionCredential(String certificateLocation) {
		return getSaml2Credential(certificateLocation, Saml2X509Credential.Saml2X509CredentialType.ENCRYPTION);
	}

	private static Saml2X509Credential getSaml2SigningCredential(String privateKeyLocation,
			String certificateLocation) {
		return getSaml2Credential(privateKeyLocation, certificateLocation,
				Saml2X509Credential.Saml2X509CredentialType.SIGNING);
	}

	private static Saml2X509Credential getSaml2DecryptionCredential(String privateKeyLocation,
			String certificateLocation) {
		return getSaml2Credential(privateKeyLocation, certificateLocation,
				Saml2X509Credential.Saml2X509CredentialType.DECRYPTION);
	}

	private static Saml2X509Credential getSaml2Credential(String privateKeyLocation, String certificateLocation,
			Saml2X509Credential.Saml2X509CredentialType credentialType) {
		RSAPrivateKey privateKey = readPrivateKey(privateKeyLocation);
		X509Certificate certificate = readCertificate(certificateLocation);
		return new Saml2X509Credential(privateKey, certificate, credentialType);
	}

	private static Saml2X509Credential getSaml2Credential(String certificateLocation,
			Saml2X509Credential.Saml2X509CredentialType credentialType) {
		X509Certificate certificate = readCertificate(certificateLocation);
		return new Saml2X509Credential(certificate, credentialType);
	}

	private static RSAPrivateKey readPrivateKey(String privateKeyLocation) {
		Resource privateKey = resourceLoader.getResource(privateKeyLocation);
		try (InputStream inputStream = privateKey.getInputStream()) {
			return RsaKeyConverters.pkcs8().convert(inputStream);
		}
		catch (Exception ex) {
			throw new IllegalArgumentException(ex);
		}
	}

	private static X509Certificate readCertificate(String certificateLocation) {
		Resource certificate = resourceLoader.getResource(certificateLocation);
		try (InputStream inputStream = certificate.getInputStream()) {
			return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(inputStream);
		}
		catch (Exception ex) {
			throw new IllegalArgumentException(ex);
		}
	}

}
