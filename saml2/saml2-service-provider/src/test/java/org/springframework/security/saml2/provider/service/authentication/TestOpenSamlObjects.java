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
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.namespace.QName;

import org.apache.xml.security.encryption.XMLCipherParameters;
import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.XSBoolean;
import org.opensaml.core.xml.schema.XSBooleanValue;
import org.opensaml.core.xml.schema.XSDateTime;
import org.opensaml.core.xml.schema.XSInteger;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.XSURI;
import org.opensaml.core.xml.schema.impl.XSAnyBuilder;
import org.opensaml.core.xml.schema.impl.XSBooleanBuilder;
import org.opensaml.core.xml.schema.impl.XSDateTimeBuilder;
import org.opensaml.core.xml.schema.impl.XSIntegerBuilder;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.opensaml.core.xml.schema.impl.XSURIBuilder;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.common.assertion.ValidationContext;
import org.opensaml.saml.saml2.assertion.SAML2AssertionValidationParameters;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.EncryptedAttribute;
import org.opensaml.saml.saml2.core.EncryptedID;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml.saml2.core.impl.AttributeStatementBuilder;
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
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.core.TestSaml2X509Credentials;

public final class TestOpenSamlObjects {

	static {
		OpenSamlInitializationService.initialize();
	}
	private static String USERNAME = "test@saml.user";

	private static String DESTINATION = "https://localhost/login/saml2/sso/idp-alias";

	private static String RELYING_PARTY_ENTITY_ID = "https://localhost/saml2/service-provider-metadata/idp-alias";

	private static String ASSERTING_PARTY_ENTITY_ID = "https://some.idp.test/saml2/idp";

	private static SecretKey SECRET_KEY = new SecretKeySpec(
			Base64.getDecoder().decode("shOnwNMoCv88HKMEa91+FlYoD5RNvzMTAL5LGxZKIFk="), "AES");

	private TestOpenSamlObjects() {
	}

	static Response response() {
		return response(DESTINATION, ASSERTING_PARTY_ENTITY_ID);
	}

	static Response response(String destination, String issuerEntityId) {
		Response response = build(Response.DEFAULT_ELEMENT_NAME);
		response.setID("R" + UUID.randomUUID().toString());
		response.setIssueInstant(DateTime.now());
		response.setVersion(SAMLVersion.VERSION_20);
		response.setID("_" + UUID.randomUUID().toString());
		response.setDestination(destination);
		response.setIssuer(issuer(issuerEntityId));
		return response;
	}

	static Response signedResponseWithOneAssertion() {
		Response response = response();
		response.getAssertions().add(assertion());
		return signed(response, TestSaml2X509Credentials.assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID);
	}

	static Assertion assertion() {
		return assertion(USERNAME, ASSERTING_PARTY_ENTITY_ID, RELYING_PARTY_ENTITY_ID, DESTINATION);
	}

	static Assertion assertion(String username, String issuerEntityId, String recipientEntityId, String recipientUri) {
		Assertion assertion = build(Assertion.DEFAULT_ELEMENT_NAME);
		assertion.setID("A" + UUID.randomUUID().toString());
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
		Issuer issuer = build(Issuer.DEFAULT_ELEMENT_NAME);
		issuer.setValue(entityId);
		return issuer;
	}

	static Subject subject(String principalName) {
		Subject subject = build(Subject.DEFAULT_ELEMENT_NAME);
		if (principalName != null) {
			subject.setNameID(nameId(principalName));
		}
		return subject;
	}

	static NameID nameId(String principalName) {
		NameID nameId = build(NameID.DEFAULT_ELEMENT_NAME);
		nameId.setValue(principalName);
		return nameId;
	}

	static SubjectConfirmation subjectConfirmation() {
		return build(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
	}

	static SubjectConfirmationData subjectConfirmationData(String recipient) {
		SubjectConfirmationData subject = build(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
		subject.setRecipient(recipient);
		subject.setNotBefore(DateTime.now().minus(Duration.millis(5 * 60 * 1000)));
		subject.setNotOnOrAfter(DateTime.now().plus(Duration.millis(5 * 60 * 1000)));
		return subject;
	}

	static Conditions conditions() {
		Conditions conditions = build(Conditions.DEFAULT_ELEMENT_NAME);
		conditions.setNotBefore(DateTime.now().minus(Duration.millis(5 * 60 * 1000)));
		conditions.setNotOnOrAfter(DateTime.now().plus(Duration.millis(5 * 60 * 1000)));
		return conditions;
	}

	public static AuthnRequest authnRequest() {
		Issuer issuer = build(Issuer.DEFAULT_ELEMENT_NAME);
		issuer.setValue(ASSERTING_PARTY_ENTITY_ID);
		AuthnRequest authnRequest = build(AuthnRequest.DEFAULT_ELEMENT_NAME);
		authnRequest.setIssuer(issuer);
		authnRequest.setDestination(ASSERTING_PARTY_ENTITY_ID + "/SSO.saml2");
		authnRequest.setAssertionConsumerServiceURL(DESTINATION);
		return authnRequest;
	}

	static Credential getSigningCredential(Saml2X509Credential credential, String entityId) {
		BasicCredential cred = getBasicCredential(credential);
		cred.setEntityId(entityId);
		cred.setUsageType(UsageType.SIGNING);
		return cred;
	}

	static Credential getSigningCredential(
			org.springframework.security.saml2.credentials.Saml2X509Credential credential, String entityId) {
		BasicCredential cred = getBasicCredential(credential);
		cred.setEntityId(entityId);
		cred.setUsageType(UsageType.SIGNING);
		return cred;
	}

	static BasicCredential getBasicCredential(Saml2X509Credential credential) {
		return CredentialSupport.getSimpleCredential(credential.getCertificate(), credential.getPrivateKey());
	}

	static BasicCredential getBasicCredential(
			org.springframework.security.saml2.credentials.Saml2X509Credential credential) {
		return CredentialSupport.getSimpleCredential(credential.getCertificate(), credential.getPrivateKey());
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
		}
		catch (MarshallingException | SignatureException | SecurityException ex) {
			throw new Saml2Exception(ex);
		}
		return signable;
	}

	static <T extends SignableSAMLObject> T signed(T signable,
			org.springframework.security.saml2.credentials.Saml2X509Credential credential, String entityId) {
		SignatureSigningParameters parameters = new SignatureSigningParameters();
		Credential signingCredential = getSigningCredential(credential, entityId);
		parameters.setSigningCredential(signingCredential);
		parameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
		parameters.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
		parameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		try {
			SignatureSupport.signObject(signable, parameters);
		}
		catch (MarshallingException | SignatureException | SecurityException ex) {
			throw new Saml2Exception(ex);
		}
		return signable;
	}

	static EncryptedAssertion encrypted(Assertion assertion, Saml2X509Credential credential) {
		X509Certificate certificate = credential.getCertificate();
		Encrypter encrypter = getEncrypter(certificate);
		try {
			return encrypter.encrypt(assertion);
		}
		catch (EncryptionException ex) {
			throw new Saml2Exception("Unable to encrypt assertion.", ex);
		}
	}

	static EncryptedAssertion encrypted(Assertion assertion,
			org.springframework.security.saml2.credentials.Saml2X509Credential credential) {
		X509Certificate certificate = credential.getCertificate();
		Encrypter encrypter = getEncrypter(certificate);
		try {
			return encrypter.encrypt(assertion);
		}
		catch (EncryptionException ex) {
			throw new Saml2Exception("Unable to encrypt assertion.", ex);
		}
	}

	static EncryptedID encrypted(NameID nameId, Saml2X509Credential credential) {
		X509Certificate certificate = credential.getCertificate();
		Encrypter encrypter = getEncrypter(certificate);
		try {
			return encrypter.encrypt(nameId);
		}
		catch (EncryptionException ex) {
			throw new Saml2Exception("Unable to encrypt nameID.", ex);
		}
	}

	static EncryptedID encrypted(NameID nameId,
			org.springframework.security.saml2.credentials.Saml2X509Credential credential) {
		X509Certificate certificate = credential.getCertificate();
		Encrypter encrypter = getEncrypter(certificate);
		try {
			return encrypter.encrypt(nameId);
		}
		catch (EncryptionException ex) {
			throw new Saml2Exception("Unable to encrypt nameID.", ex);
		}
	}

	static EncryptedAttribute encrypted(String name, String value, Saml2X509Credential credential) {
		Attribute attribute = attribute(name, value);
		X509Certificate certificate = credential.getCertificate();
		Encrypter encrypter = getEncrypter(certificate);
		try {
			return encrypter.encrypt(attribute);
		}
		catch (EncryptionException ex) {
			throw new Saml2Exception("Unable to encrypt nameID.", ex);
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

	static Attribute attribute(String name, String value) {
		Attribute attribute = build(Attribute.DEFAULT_ELEMENT_NAME);
		attribute.setName(name);
		XSString xsValue = new XSStringBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
		xsValue.setValue(value);
		attribute.getAttributeValues().add(xsValue);
		return attribute;
	}

	static List<AttributeStatement> attributeStatements() {
		List<AttributeStatement> attributeStatements = new ArrayList<>();
		AttributeStatementBuilder attributeStatementBuilder = new AttributeStatementBuilder();
		AttributeBuilder attributeBuilder = new AttributeBuilder();
		AttributeStatement attrStmt1 = attributeStatementBuilder.buildObject();
		Attribute emailAttr = attributeBuilder.buildObject();
		emailAttr.setName("email");
		XSAny email1 = new XSAnyBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSAny.TYPE_NAME); // gh-8864
		email1.setTextContent("john.doe@example.com");
		emailAttr.getAttributeValues().add(email1);
		XSAny email2 = new XSAnyBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME);
		email2.setTextContent("doe.john@example.com");
		emailAttr.getAttributeValues().add(email2);
		attrStmt1.getAttributes().add(emailAttr);
		Attribute nameAttr = attributeBuilder.buildObject();
		nameAttr.setName("name");
		XSString name = new XSStringBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
		name.setValue("John Doe");
		nameAttr.getAttributeValues().add(name);
		attrStmt1.getAttributes().add(nameAttr);
		Attribute ageAttr = attributeBuilder.buildObject();
		ageAttr.setName("age");
		XSInteger age = new XSIntegerBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSInteger.TYPE_NAME);
		age.setValue(21);
		ageAttr.getAttributeValues().add(age);
		attrStmt1.getAttributes().add(ageAttr);
		attributeStatements.add(attrStmt1);
		AttributeStatement attrStmt2 = attributeStatementBuilder.buildObject();
		Attribute websiteAttr = attributeBuilder.buildObject();
		websiteAttr.setName("website");
		XSURI uri = new XSURIBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSURI.TYPE_NAME);
		uri.setValue("https://johndoe.com/");
		websiteAttr.getAttributeValues().add(uri);
		attrStmt2.getAttributes().add(websiteAttr);
		Attribute registeredAttr = attributeBuilder.buildObject();
		registeredAttr.setName("registered");
		XSBoolean registered = new XSBooleanBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
				XSBoolean.TYPE_NAME);
		registered.setValue(new XSBooleanValue(true, false));
		registeredAttr.getAttributeValues().add(registered);
		attrStmt2.getAttributes().add(registeredAttr);
		Attribute registeredDateAttr = attributeBuilder.buildObject();
		registeredDateAttr.setName("registeredDate");
		XSDateTime registeredDate = new XSDateTimeBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
				XSDateTime.TYPE_NAME);
		registeredDate.setValue(DateTime.parse("1970-01-01T00:00:00Z"));
		registeredDateAttr.getAttributeValues().add(registeredDate);
		attrStmt2.getAttributes().add(registeredDateAttr);
		attributeStatements.add(attrStmt2);
		return attributeStatements;
	}

	static ValidationContext validationContext() {
		Map<String, Object> params = new HashMap<>();
		params.put(SAML2AssertionValidationParameters.SC_VALID_RECIPIENTS, Collections.singleton(DESTINATION));
		return new ValidationContext(params);
	}

	static <T extends XMLObject> T build(QName qName) {
		return (T) XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(qName).buildObject(qName);
	}

}
