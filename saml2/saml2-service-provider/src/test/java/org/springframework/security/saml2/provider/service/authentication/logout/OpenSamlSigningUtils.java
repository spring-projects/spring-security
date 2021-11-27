/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.saml2.provider.service.authentication.logout;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.security.impl.SAMLMetadataSignatureSigningParametersResolver;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.SignatureSigningParametersResolver;
import org.opensaml.xmlsec.criterion.SignatureSigningConfigurationCriterion;
import org.opensaml.xmlsec.crypto.XMLSigningUtil;
import org.opensaml.xmlsec.impl.BasicSignatureSigningConfiguration;
import org.opensaml.xmlsec.keyinfo.KeyInfoGeneratorManager;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.SignableXMLObject;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.w3c.dom.Element;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

/**
 * Utility methods for signing SAML components with OpenSAML
 *
 * For internal use only.
 *
 * @author Josh Cummings
 */
final class OpenSamlSigningUtils {

	static String serialize(XMLObject object) {
		try {
			Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
			Element element = marshaller.marshall(object);
			return SerializeSupport.nodeToString(element);
		}
		catch (MarshallingException ex) {
			throw new Saml2Exception(ex);
		}
	}

	static <O extends SignableXMLObject> O sign(O object, RelyingPartyRegistration relyingPartyRegistration) {
		SignatureSigningParameters parameters = resolveSigningParameters(relyingPartyRegistration);
		try {
			SignatureSupport.signObject(object, parameters);
			return object;
		}
		catch (Exception ex) {
			throw new Saml2Exception(ex);
		}
	}

	static QueryParametersPartial sign(RelyingPartyRegistration registration) {
		return new QueryParametersPartial(registration);
	}

	private static SignatureSigningParameters resolveSigningParameters(
			RelyingPartyRegistration relyingPartyRegistration) {
		List<Credential> credentials = resolveSigningCredentials(relyingPartyRegistration);
		List<String> algorithms = relyingPartyRegistration.getAssertingPartyDetails().getSigningAlgorithms();
		List<String> digests = Collections.singletonList(SignatureConstants.ALGO_ID_DIGEST_SHA256);
		String canonicalization = SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;
		SignatureSigningParametersResolver resolver = new SAMLMetadataSignatureSigningParametersResolver();
		CriteriaSet criteria = new CriteriaSet();
		BasicSignatureSigningConfiguration signingConfiguration = new BasicSignatureSigningConfiguration();
		signingConfiguration.setSigningCredentials(credentials);
		signingConfiguration.setSignatureAlgorithms(algorithms);
		signingConfiguration.setSignatureReferenceDigestMethods(digests);
		signingConfiguration.setSignatureCanonicalizationAlgorithm(canonicalization);
		signingConfiguration.setKeyInfoGeneratorManager(buildSignatureKeyInfoGeneratorManager());
		criteria.add(new SignatureSigningConfigurationCriterion(signingConfiguration));
		try {
			SignatureSigningParameters parameters = resolver.resolveSingle(criteria);
			Assert.notNull(parameters, "Failed to resolve any signing credential");
			return parameters;
		}
		catch (Exception ex) {
			throw new Saml2Exception(ex);
		}
	}

	private static NamedKeyInfoGeneratorManager buildSignatureKeyInfoGeneratorManager() {
		final NamedKeyInfoGeneratorManager namedManager = new NamedKeyInfoGeneratorManager();

		namedManager.setUseDefaultManager(true);
		final KeyInfoGeneratorManager defaultManager = namedManager.getDefaultManager();

		// Generator for X509Credentials
		final X509KeyInfoGeneratorFactory x509Factory = new X509KeyInfoGeneratorFactory();
		x509Factory.setEmitEntityCertificate(true);
		x509Factory.setEmitEntityCertificateChain(true);

		defaultManager.registerFactory(x509Factory);

		return namedManager;
	}

	private static List<Credential> resolveSigningCredentials(RelyingPartyRegistration relyingPartyRegistration) {
		List<Credential> credentials = new ArrayList<>();
		for (Saml2X509Credential x509Credential : relyingPartyRegistration.getSigningX509Credentials()) {
			X509Certificate certificate = x509Credential.getCertificate();
			PrivateKey privateKey = x509Credential.getPrivateKey();
			BasicCredential credential = CredentialSupport.getSimpleCredential(certificate, privateKey);
			credential.setEntityId(relyingPartyRegistration.getEntityId());
			credential.setUsageType(UsageType.SIGNING);
			credentials.add(credential);
		}
		return credentials;
	}

	private OpenSamlSigningUtils() {

	}

	static class QueryParametersPartial {

		final RelyingPartyRegistration registration;

		final Map<String, String> components = new LinkedHashMap<>();

		QueryParametersPartial(RelyingPartyRegistration registration) {
			this.registration = registration;
		}

		QueryParametersPartial param(String key, String value) {
			this.components.put(key, value);
			return this;
		}

		Map<String, String> parameters() {
			SignatureSigningParameters parameters = resolveSigningParameters(this.registration);
			Credential credential = parameters.getSigningCredential();
			String algorithmUri = parameters.getSignatureAlgorithm();
			this.components.put(Saml2ParameterNames.SIG_ALG, algorithmUri);
			UriComponentsBuilder builder = UriComponentsBuilder.newInstance();
			for (Map.Entry<String, String> component : this.components.entrySet()) {
				builder.queryParam(component.getKey(),
						UriUtils.encode(component.getValue(), StandardCharsets.ISO_8859_1));
			}
			String queryString = builder.build(true).toString().substring(1);
			try {
				byte[] rawSignature = XMLSigningUtil.signWithURI(credential, algorithmUri,
						queryString.getBytes(StandardCharsets.UTF_8));
				String b64Signature = Saml2Utils.samlEncode(rawSignature);
				this.components.put(Saml2ParameterNames.SIGNATURE, b64Signature);
			}
			catch (SecurityException ex) {
				throw new Saml2Exception(ex);
			}
			return this.components;
		}

	}

}
