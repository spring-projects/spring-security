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

import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.xml.namespace.QName;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.AuthnRequest;
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
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.util.Assert;
import org.springframework.web.util.UriUtils;

import static java.util.Arrays.asList;
import static org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport.getBuilderFactory;
import static org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport.getParserPool;
import static org.springframework.util.StringUtils.hasText;

/**
 * @since 5.2
 */
final class OpenSamlImplementation {
	private static OpenSamlImplementation instance = new OpenSamlImplementation();

	private final EncryptedKeyResolver encryptedKeyResolver = new ChainingEncryptedKeyResolver(
			asList(
					new InlineEncryptedKeyResolver(),
					new EncryptedElementTypeEncryptedKeyResolver(),
					new SimpleRetrievalMethodEncryptedKeyResolver()
			)
	);

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

	<T> T buildSamlObject(QName qName) {
		return (T) getBuilderFactory().getBuilder(qName).buildObject(qName);
	}

	XMLObject resolve(String xml) {
		return resolve(xml.getBytes(StandardCharsets.UTF_8));
	}

	String serialize(XMLObject xmlObject) {
		final MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
		try {
			Element element = marshallerFactory.getMarshaller(xmlObject).marshall(xmlObject);
			return SerializeSupport.nodeToString(element);
		} catch (MarshallingException e) {
			throw new Saml2Exception(e);
		}
	}

	String serialize(AuthnRequest authnRequest, List<Saml2X509Credential> signingCredentials) {
		if (hasSigningCredential(signingCredentials) != null) {
			signAuthnRequest(authnRequest, signingCredentials);
		}
		return serialize(authnRequest);
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
			Document document = getParserPool().parse(new ByteArrayInputStream(xml));
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

	private void signAuthnRequest(AuthnRequest authnRequest, List<Saml2X509Credential> signingCredentials) {
		SignatureSigningParameters parameters = new SignatureSigningParameters();
		Credential credential = getSigningCredential(signingCredentials, authnRequest.getIssuer().getValue());
		parameters.setSigningCredential(credential);
		parameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
		parameters.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
		parameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		try {
			SignatureSupport.signObject(authnRequest, parameters);
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
