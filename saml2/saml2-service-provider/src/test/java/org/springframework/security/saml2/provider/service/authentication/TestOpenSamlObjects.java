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

import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.UUID;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.xml.security.encryption.XMLCipherParameters;
import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.EncryptedID;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureSupport;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.credentials.Saml2X509Credential;

final class TestOpenSamlObjects {
	private static OpenSamlImplementation saml = OpenSamlImplementation.getInstance();

	private static String USERNAME = "test@saml.user";
	private static String DESTINATION = "https://localhost/login/saml2/sso/idp-alias";
	private static String RELYING_PARTY_ENTITY_ID = "https://localhost/saml2/service-provider-metadata/idp-alias";
	private static String ASSERTING_PARTY_ENTITY_ID = "https://some.idp.test/saml2/idp";
	private static SecretKey SECRET_KEY =
			new SecretKeySpec(Base64.getDecoder().decode("shOnwNMoCv88HKMEa91+FlYoD5RNvzMTAL5LGxZKIFk="), "AES");

	static Response response() {
		return response(DESTINATION, ASSERTING_PARTY_ENTITY_ID);
	}

	static Response response(String destination, String issuerEntityId) {
		Response response = saml.buildSamlObject(Response.DEFAULT_ELEMENT_NAME);
		response.setID("R"+UUID.randomUUID().toString());
		response.setIssueInstant(DateTime.now());
		response.setVersion(SAMLVersion.VERSION_20);
		response.setID("_" + UUID.randomUUID().toString());
		response.setDestination(destination);
		response.setIssuer(issuer(issuerEntityId));
		return response;
	}

	static Assertion assertion() {
		return assertion(USERNAME, ASSERTING_PARTY_ENTITY_ID, RELYING_PARTY_ENTITY_ID, DESTINATION);
	}

	static Assertion assertion(
			String username,
			String issuerEntityId,
			String recipientEntityId,
			String recipientUri
	) {
		Assertion assertion = saml.buildSamlObject(Assertion.DEFAULT_ELEMENT_NAME);
		assertion.setID("A"+ UUID.randomUUID().toString());
		assertion.setIssueInstant(DateTime.now());
		assertion.setVersion(SAMLVersion.VERSION_20);
		assertion.setIssueInstant(DateTime.now());
		assertion.setIssuer(issuer(issuerEntityId));
		assertion.setSubject(subject(username));
		assertion.setConditions(conditions());

		SubjectConfirmation subjectConfirmation = subjectConfirmation();
		subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
		SubjectConfirmationData confirmationData = subjectConfirmationData(recipientEntityId);
		confirmationData.setRecipient(recipientUri);
		subjectConfirmation.setSubjectConfirmationData(confirmationData);
		assertion.getSubject().getSubjectConfirmations().add(subjectConfirmation);
		return assertion;
	}


	static Issuer issuer(String entityId) {
		Issuer issuer = saml.buildSamlObject(Issuer.DEFAULT_ELEMENT_NAME);
		issuer.setValue(entityId);
		return issuer;
	}

	static Subject subject(String principalName) {
		Subject subject = saml.buildSamlObject(Subject.DEFAULT_ELEMENT_NAME);

		if (principalName != null) {
			subject.setNameID(nameId(principalName));
		}

		return subject;
	}

	static NameID nameId(String principalName) {
		NameID nameId = saml.buildSamlObject(NameID.DEFAULT_ELEMENT_NAME);
		nameId.setValue(principalName);
		return nameId;
	}

	static SubjectConfirmation subjectConfirmation() {
		return saml.buildSamlObject(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
	}

	static SubjectConfirmationData subjectConfirmationData(String recipient) {
		SubjectConfirmationData subject = saml.buildSamlObject(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
		subject.setRecipient(recipient);
		subject.setNotBefore(DateTime.now().minus(Duration.millis(5 * 60 * 1000)));
		subject.setNotOnOrAfter(DateTime.now().plus(Duration.millis(5 * 60 * 1000)));
		return subject;
	}

	static Conditions conditions() {
		Conditions conditions = saml.buildSamlObject(Conditions.DEFAULT_ELEMENT_NAME);
		conditions.setNotBefore(DateTime.now().minus(Duration.millis(5 * 60 * 1000)));
		conditions.setNotOnOrAfter(DateTime.now().plus(Duration.millis(5 * 60 * 1000)));
		return conditions;
	}

	static Credential getSigningCredential(Saml2X509Credential credential, String entityId) {
		BasicCredential cred = getBasicCredential(credential);
		cred.setEntityId(entityId);
		cred.setUsageType(UsageType.SIGNING);
		return cred;
	}

	static BasicCredential getBasicCredential(Saml2X509Credential credential) {
		return CredentialSupport.getSimpleCredential(
				credential.getCertificate(),
				credential.getPrivateKey()
		);
	}

	static <T extends SignableSAMLObject> T signed(T signable, Saml2X509Credential credential, String entityId) {
		SignatureSigningParameters parameters = new SignatureSigningParameters();
		Credential signingCredential = getSigningCredential(credential, entityId);
		parameters.setSigningCredential(signingCredential);
		parameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
		parameters.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
		parameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		try {
			SignatureSupport.signObject(signable, parameters);
		} catch (MarshallingException | SignatureException | SecurityException e) {
			throw new Saml2Exception(e);
		}

		return signable;
	}

	static EncryptedAssertion encrypted(Assertion assertion, Saml2X509Credential credential) {
		X509Certificate certificate = credential.getCertificate();
		Encrypter encrypter = getEncrypter(certificate);
		try {
			return encrypter.encrypt(assertion);
		}
		catch (EncryptionException e) {
			throw new Saml2Exception("Unable to encrypt assertion.", e);
		}
	}

	static EncryptedID encrypted(NameID nameId, Saml2X509Credential credential) {
		X509Certificate certificate = credential.getCertificate();
		Encrypter encrypter = getEncrypter(certificate);
		try {
			return encrypter.encrypt(nameId);
		}
		catch (EncryptionException e) {
			throw new Saml2Exception("Unable to encrypt nameID.", e);
		}
	}

	private static Encrypter getEncrypter(X509Certificate certificate) {
		String dataAlgorithm = XMLCipherParameters.AES_256;
		String keyAlgorithm = XMLCipherParameters.RSA_1_5;

		BasicCredential dataCredential = new BasicCredential(SECRET_KEY);
		DataEncryptionParameters dataEncryptionParameters = new DataEncryptionParameters();
		dataEncryptionParameters.setEncryptionCredential(dataCredential);
		dataEncryptionParameters.setAlgorithm(dataAlgorithm);

		Credential credential = CredentialSupport.getSimpleCredential(certificate, null);
		KeyEncryptionParameters keyEncryptionParameters = new KeyEncryptionParameters();
		keyEncryptionParameters.setEncryptionCredential(credential);
		keyEncryptionParameters.setAlgorithm(keyAlgorithm);

		Encrypter encrypter = new Encrypter(dataEncryptionParameters, keyEncryptionParameters);
		Encrypter.KeyPlacement keyPlacement = Encrypter.KeyPlacement.valueOf("PEER");
		encrypter.setKeyPlacement(keyPlacement);

		return encrypter;
	}
}
