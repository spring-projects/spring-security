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

package org.springframework.security.saml2.provider.service.authentication;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.crypto.XMLSigningUtil;
import org.opensaml.xmlsec.encryption.support.ChainingEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.EncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.Saml2Utils;
import org.springframework.util.Assert;
import org.springframework.web.util.UriUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import static java.util.Arrays.asList;
import static org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport.getBuilderFactory;
import static org.springframework.util.StringUtils.hasText;

/**
 * @since 5.2
 */
final class OpenSamlImplementation {
	private static OpenSamlImplementation instance = new OpenSamlImplementation();

	private final BasicParserPool parserPool = new BasicParserPool();
	private final EncryptedKeyResolver encryptedKeyResolver = new ChainingEncryptedKeyResolver(
			asList(
					new InlineEncryptedKeyResolver(),
					new EncryptedElementTypeEncryptedKeyResolver(),
					new SimpleRetrievalMethodEncryptedKeyResolver()
			)
	);

	private OpenSamlImplementation() {
		bootstrap();
	}

	/*
	 * ==============================================================
	 * PRIVATE METHODS
	 * ==============================================================
	 */
	private void bootstrap() {
		// configure default values
		// maxPoolSize = 5;
		this.parserPool.setMaxPoolSize(50);
		// coalescing = true;
		this.parserPool.setCoalescing(true);
		// expandEntityReferences = false;
		this.parserPool.setExpandEntityReferences(false);
		// ignoreComments = true;
		this.parserPool.setIgnoreComments(true);
		// ignoreElementContentWhitespace = true;
		this.parserPool.setIgnoreElementContentWhitespace(true);
		// namespaceAware = true;
		this.parserPool.setNamespaceAware(true);
		// schema = null;
		this.parserPool.setSchema(null);
		// dtdValidating = false;
		this.parserPool.setDTDValidating(false);
		// xincludeAware = false;
		this.parserPool.setXincludeAware(false);

		Map<String, Object> builderAttributes = new HashMap<>();
		this.parserPool.setBuilderAttributes(builderAttributes);

		Map<String, Boolean> parserBuilderFeatures = new HashMap<>();
		parserBuilderFeatures.put("http://apache.org/xml/features/disallow-doctype-decl", TRUE);
		parserBuilderFeatures.put(XMLConstants.FEATURE_SECURE_PROCESSING, TRUE);
		parserBuilderFeatures.put("http://xml.org/sax/features/external-general-entities", FALSE);
		parserBuilderFeatures.put("http://apache.org/xml/features/validation/schema/normalized-value", FALSE);
		parserBuilderFeatures.put("http://xml.org/sax/features/external-parameter-entities", FALSE);
		parserBuilderFeatures.put("http://apache.org/xml/features/dom/defer-node-expansion", FALSE);
		this.parserPool.setBuilderFeatures(parserBuilderFeatures);

		try {
			this.parserPool.initialize();
		}
		catch (ComponentInitializationException x) {
			throw new Saml2Exception("Unable to initialize OpenSaml v3 ParserPool", x);
		}

		try {
			InitializationService.initialize();
		}
		catch (InitializationException e) {
			throw new Saml2Exception("Unable to initialize OpenSaml v3", e);
		}

		XMLObjectProviderRegistry registry;
		synchronized (ConfigurationService.class) {
			registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
			if (registry == null) {
				registry = new XMLObjectProviderRegistry();
				ConfigurationService.register(XMLObjectProviderRegistry.class, registry);
			}
		}

		registry.setParserPool(this.parserPool);
	}

	/*
	 * ==============================================================
	 * PUBLIC METHODS
	 * ==============================================================
	 */
	static OpenSamlImplementation getInstance() {
		return instance;
	}

	EncryptedKeyResolver getEncryptedKeyResolver() {
		return this.encryptedKeyResolver;
	}

	<T> T buildSAMLObject(final Class<T> clazz) {
		try {
			QName defaultElementName = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
			return (T) getBuilderFactory().getBuilder(defaultElementName).buildObject(defaultElementName);
		}
		catch (NoSuchFieldException | IllegalAccessException e) {
			throw new Saml2Exception("Could not create SAML object", e);
		}
	}

	XMLObject resolve(String xml) {
		return resolve(xml.getBytes(StandardCharsets.UTF_8));
	}

	String toXml(XMLObject object, List<Saml2X509Credential> signingCredentials, String localSpEntityId) {
		if (object instanceof SignableSAMLObject && null != hasSigningCredential(signingCredentials)) {
			signXmlObject(
					(SignableSAMLObject) object,
					signingCredentials,
					localSpEntityId
			);
		}
		final MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
		try {
			Element element = marshallerFactory.getMarshaller(object).marshall(object);
			return SerializeSupport.nodeToString(element);
		} catch (MarshallingException e) {
			throw new Saml2Exception(e);
		}
	}

	/**
	 * Returns query parameter after creating a Query String signature
	 * All return values are unencoded and will need to be encoded prior to sending
	 * The methods {@link UriUtils#encode(String, Charset)} and {@link UriUtils#decode(String, Charset)}
	 * with the {@link StandardCharsets#ISO_8859_1} character set are used for all URL encoding/decoding.
	 * @param signingCredentials - credentials to be used for signature
	 * @return a map of unencoded query parameters with the following keys:
	 * {@code {SAMLRequest, RelayState (may be null)}, SigAlg, Signature}
	 *
	 */
	Map<String, String> signQueryParameters(
			List<Saml2X509Credential> signingCredentials,
			String samlRequest,
			String relayState) {
		Assert.notNull(samlRequest, "samlRequest cannot be null");
		String algorithmUri = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
		StringBuilder queryString = new StringBuilder();
		queryString
				.append("SAMLRequest")
				.append("=")
				.append(UriUtils.encode(samlRequest, StandardCharsets.ISO_8859_1))
				.append("&");
		if (hasText(relayState)) {
			queryString
					.append("RelayState")
					.append("=")
					.append(UriUtils.encode(relayState, StandardCharsets.ISO_8859_1))
					.append("&");
		}
		queryString
				.append("SigAlg")
				.append("=")
				.append(UriUtils.encode(algorithmUri, StandardCharsets.ISO_8859_1));

		try {
			byte[] rawSignature = XMLSigningUtil.signWithURI(
					getSigningCredential(signingCredentials, ""),
					algorithmUri,
					queryString.toString().getBytes(StandardCharsets.UTF_8)
			);
			String b64Signature = Saml2Utils.samlEncode(rawSignature);

			Map<String, String> result = new LinkedHashMap<>();
			result.put("SAMLRequest", samlRequest);
			if (hasText(relayState)) {
				result.put("RelayState", relayState);
			}
			result.put("SigAlg", algorithmUri);
			result.put("Signature", b64Signature);
			return result;
		}
		catch (SecurityException e) {
			throw new Saml2Exception(e);
		}
	}

	/*
	 * ==============================================================
	 * PRIVATE METHODS
	 * ==============================================================
	 */

	private XMLObject resolve(byte[] xml) {
		XMLObject parsed = parse(xml);
		if (parsed != null) {
			return parsed;
		}
		throw new Saml2Exception("Deserialization not supported for given data set");
	}

	private XMLObject parse(byte[] xml) {
		try {
			Document document = this.parserPool.parse(new ByteArrayInputStream(xml));
			Element element = document.getDocumentElement();
			return getUnmarshallerFactory().getUnmarshaller(element).unmarshall(element);
		}
		catch (UnmarshallingException | XMLParserException e) {
			throw new Saml2Exception(e);
		}
	}

	private UnmarshallerFactory getUnmarshallerFactory() {
		return XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
	}


	private Saml2X509Credential hasSigningCredential(List<Saml2X509Credential> credentials) {
		for (Saml2X509Credential c : credentials) {
			if (c.isSigningCredential()) {
				return c;
			}
		}
		return null;
	}

	private Credential getSigningCredential(List<Saml2X509Credential> signingCredential,
											String localSpEntityId
	) {
		Saml2X509Credential credential = hasSigningCredential(signingCredential);
		if (credential == null) {
			throw new Saml2Exception("no signing credential configured");
		}
		BasicCredential cred = getBasicCredential(credential);
		cred.setEntityId(localSpEntityId);
		cred.setUsageType(UsageType.SIGNING);
		return cred;
	}

	private void signXmlObject(SignableSAMLObject object, List<Saml2X509Credential> signingCredentials, String entityId) {
		SignatureSigningParameters parameters = new SignatureSigningParameters();
		Credential credential = getSigningCredential(signingCredentials, entityId);
		parameters.setSigningCredential(credential);
		parameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
		parameters.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
		parameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		try {
			SignatureSupport.signObject(object, parameters);
		} catch (MarshallingException | SignatureException | SecurityException e) {
			throw new Saml2Exception(e);
		}

	}

	private BasicX509Credential getBasicCredential(Saml2X509Credential credential) {
		return CredentialSupport.getSimpleCredential(
				credential.getCertificate(),
				credential.getPrivateKey()
		);
	}

}
