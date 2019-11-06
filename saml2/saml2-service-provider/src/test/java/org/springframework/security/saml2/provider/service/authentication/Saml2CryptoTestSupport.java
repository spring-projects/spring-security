/*
 * Copyright 2002-2019 the original author or authors.
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

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.credentials.Saml2X509Credential;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.encryption.XMLCipherParameters;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.EncryptedID;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureSupport;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.crypto.SecretKey;

import static java.util.Arrays.asList;
import static org.opensaml.security.crypto.KeySupport.generateKey;

final class Saml2CryptoTestSupport {
	static void signXmlObject(SignableSAMLObject object, List<Saml2X509Credential> signingCredentials, String entityId) {
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

	static EncryptedAssertion encryptAssertion(Assertion assertion, List<Saml2X509Credential> encryptionCredentials) {
		X509Certificate certificate = getEncryptionCertificate(encryptionCredentials);
		Encrypter encrypter = getEncrypter(certificate);
		try {
			Encrypter.KeyPlacement keyPlacement = Encrypter.KeyPlacement.valueOf("PEER");
			encrypter.setKeyPlacement(keyPlacement);
			return encrypter.encrypt(assertion);
		}
		catch (EncryptionException e) {
			throw new Saml2Exception("Unable to encrypt assertion.", e);
		}
	}

	static EncryptedID encryptNameId(NameID nameID, List<Saml2X509Credential> encryptionCredentials) {
		X509Certificate certificate = getEncryptionCertificate(encryptionCredentials);
		Encrypter encrypter = getEncrypter(certificate);
		try {
			Encrypter.KeyPlacement keyPlacement = Encrypter.KeyPlacement.valueOf("PEER");
			encrypter.setKeyPlacement(keyPlacement);
			return encrypter.encrypt(nameID);
		}
		catch (EncryptionException e) {
			throw new Saml2Exception("Unable to encrypt nameID.", e);
		}
	}

	private static Encrypter getEncrypter(X509Certificate certificate) {
		Credential credential = CredentialSupport.getSimpleCredential(certificate, null);
		final String dataAlgorithm = XMLCipherParameters.AES_256;
		final String keyAlgorithm = XMLCipherParameters.RSA_1_5;
		SecretKey secretKey = generateKeyFromURI(dataAlgorithm);
		BasicCredential dataCredential = new BasicCredential(secretKey);
		DataEncryptionParameters dataEncryptionParameters = new DataEncryptionParameters();
		dataEncryptionParameters.setEncryptionCredential(dataCredential);
		dataEncryptionParameters.setAlgorithm(dataAlgorithm);

		KeyEncryptionParameters keyEncryptionParameters = new KeyEncryptionParameters();
		keyEncryptionParameters.setEncryptionCredential(credential);
		keyEncryptionParameters.setAlgorithm(keyAlgorithm);

		Encrypter encrypter = new Encrypter(dataEncryptionParameters, asList(keyEncryptionParameters));

		return encrypter;
	}

	private static SecretKey generateKeyFromURI(String algoURI) {
		try {
			String jceAlgorithmName = JCEMapper.getJCEKeyAlgorithmFromURI(algoURI);
			int keyLength = JCEMapper.getKeyLengthFromURI(algoURI);
			return generateKey(jceAlgorithmName, keyLength, null);
		}
		catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new Saml2Exception(e);
		}
	}

	private static X509Certificate getEncryptionCertificate(List<Saml2X509Credential> encryptionCredentials) {
		X509Certificate certificate = null;
		for (Saml2X509Credential credential : encryptionCredentials) {
			if (credential.isEncryptionCredential()) {
				certificate = credential.getCertificate();
				break;
			}
		}
		if (certificate == null) {
			throw new Saml2Exception("No valid encryption certificate found");
		}
		return certificate;
	}

	private static Saml2X509Credential hasSigningCredential(List<Saml2X509Credential> credentials) {
		for (Saml2X509Credential c : credentials) {
			if (c.isSigningCredential()) {
				return c;
			}
		}
		return null;
	}

	private static Credential getSigningCredential(List<Saml2X509Credential> signingCredential,
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

	private static BasicX509Credential getBasicCredential(Saml2X509Credential credential) {
		return CredentialSupport.getSimpleCredential(
				credential.getCertificate(),
				credential.getPrivateKey()
		);
	}

}
