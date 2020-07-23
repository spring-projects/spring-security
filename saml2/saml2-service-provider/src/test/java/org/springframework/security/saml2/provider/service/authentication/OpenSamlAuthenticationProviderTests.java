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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.StringReader;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.EncryptedID;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.credentials.Saml2X509Credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport.getBuilderFactory;
import static org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport.getMarshallerFactory;
import static org.springframework.security.saml2.credentials.TestSaml2X509Credentials.assertingPartyEncryptingCredential;
import static org.springframework.security.saml2.credentials.TestSaml2X509Credentials.assertingPartyPrivateCredential;
import static org.springframework.security.saml2.credentials.TestSaml2X509Credentials.assertingPartySigningCredential;
import static org.springframework.security.saml2.credentials.TestSaml2X509Credentials.relyingPartyDecryptingCredential;
import static org.springframework.security.saml2.credentials.TestSaml2X509Credentials.relyingPartyVerifyingCredential;
import static org.springframework.security.saml2.provider.service.authentication.TestOpenSamlObjects.assertion;
import static org.springframework.security.saml2.provider.service.authentication.TestOpenSamlObjects.attributeStatements;
import static org.springframework.security.saml2.provider.service.authentication.TestOpenSamlObjects.encrypted;
import static org.springframework.security.saml2.provider.service.authentication.TestOpenSamlObjects.response;
import static org.springframework.security.saml2.provider.service.authentication.TestOpenSamlObjects.signed;
import static org.springframework.util.StringUtils.hasText;

/**
 * Tests for {@link OpenSamlAuthenticationProvider}
 *
 * @author Filip Hanik
 * @author Josh Cummings
 */
public class OpenSamlAuthenticationProviderTests {

	private static String DESTINATION = "https://localhost/login/saml2/sso/idp-alias";
	private static String RELYING_PARTY_ENTITY_ID = "https://localhost/saml2/service-provider-metadata/idp-alias";
	private static String ASSERTING_PARTY_ENTITY_ID = "https://some.idp.test/saml2/idp";

	private OpenSamlAuthenticationProvider provider = new OpenSamlAuthenticationProvider();

	@Rule
	public ExpectedException exception = ExpectedException.none();

	@Test
	public void supportsWhenSaml2AuthenticationTokenThenReturnTrue() {

		assertThat(this.provider.supports(Saml2AuthenticationToken.class))
				.withFailMessage(OpenSamlAuthenticationProvider.class + "should support " + Saml2AuthenticationToken.class)
				.isTrue();
	}

	@Test
	public void supportsWhenNotSaml2AuthenticationTokenThenReturnFalse() {
		assertThat(!this.provider.supports(Authentication.class))
				.withFailMessage(OpenSamlAuthenticationProvider.class + "should not support " + Authentication.class)
				.isTrue();
	}

	@Test
	public void authenticateWhenUnknownDataClassThenThrowAuthenticationException() {
		this.exception.expect(authenticationMatcher(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA));

		Assertion assertion = (Assertion) getBuilderFactory().getBuilder(Assertion.DEFAULT_ELEMENT_NAME)
				.buildObject(Assertion.DEFAULT_ELEMENT_NAME);
		this.provider.authenticate(token(serialize(assertion), relyingPartyVerifyingCredential()));
	}

	@Test
	public void authenticateWhenXmlErrorThenThrowAuthenticationException() {
		this.exception.expect(authenticationMatcher(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA));

		Saml2AuthenticationToken token = token("invalid xml", relyingPartyVerifyingCredential());
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenInvalidDestinationThenThrowAuthenticationException() {
		this.exception.expect(authenticationMatcher(Saml2ErrorCodes.INVALID_DESTINATION));

		Response response = response(DESTINATION + "invalid", ASSERTING_PARTY_ENTITY_ID);
		response.getAssertions().add(assertion());
		signed(response, assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID);
		Saml2AuthenticationToken token = token(response, relyingPartyVerifyingCredential());
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenNoAssertionsPresentThenThrowAuthenticationException() {
		this.exception.expect(
				authenticationMatcher(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA, "No assertions found in response.")
		);

		Saml2AuthenticationToken token = token(response(), assertingPartySigningCredential());
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenInvalidSignatureOnAssertionThenThrowAuthenticationException() {
		this.exception.expect(authenticationMatcher(Saml2ErrorCodes.INVALID_SIGNATURE));

		Response response = response();
		response.getAssertions().add(assertion());
		Saml2AuthenticationToken token = token(response, relyingPartyVerifyingCredential());
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenOpenSAMLValidationErrorThenThrowAuthenticationException() throws Exception {
		this.exception.expect(authenticationMatcher(Saml2ErrorCodes.INVALID_ASSERTION));

		Response response = response();
		Assertion assertion = assertion();
		assertion
				.getSubject()
				.getSubjectConfirmations()
				.get(0)
				.getSubjectConfirmationData()
				.setNotOnOrAfter(DateTime.now().minus(Duration.standardDays(3)));
		signed(assertion, assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID);
		response.getAssertions().add(assertion);
		Saml2AuthenticationToken token = token(response, relyingPartyVerifyingCredential());
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenMissingSubjectThenThrowAuthenticationException()  {
		this.exception.expect(authenticationMatcher(Saml2ErrorCodes.SUBJECT_NOT_FOUND));

		Response response = response();
		Assertion assertion = assertion();
		assertion.setSubject(null);
		signed(assertion, assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID);
		response.getAssertions().add(assertion);
		Saml2AuthenticationToken token = token(response, relyingPartyVerifyingCredential());
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenUsernameMissingThenThrowAuthenticationException() throws Exception {
		this.exception.expect(authenticationMatcher(Saml2ErrorCodes.SUBJECT_NOT_FOUND));

		Response response = response();
		Assertion assertion = assertion();
		assertion
				.getSubject()
				.getNameID()
				.setValue(null);
		signed(assertion, assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID);
		response.getAssertions().add(assertion);
		Saml2AuthenticationToken token = token(response, relyingPartyVerifyingCredential());
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenAssertionContainsValidationAddressThenItSucceeds() throws Exception {
		Response response = response();
		Assertion assertion = assertion();
		assertion.getSubject().getSubjectConfirmations().forEach(
				sc -> sc.getSubjectConfirmationData().setAddress("10.10.10.10")
		);
		signed(assertion, assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID);
		response.getAssertions().add(assertion);
		Saml2AuthenticationToken token = token(response, relyingPartyVerifyingCredential());
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenAssertionContainsAttributesThenItSucceeds() {
		Response response = response();
		Assertion assertion = assertion();
		List<AttributeStatement> attributes = attributeStatements();
		assertion.getAttributeStatements().addAll(attributes);
		signed(assertion, assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID);
		response.getAssertions().add(assertion);
		Saml2AuthenticationToken token = token(response, relyingPartyVerifyingCredential());
		Authentication authentication = this.provider.authenticate(token);
		Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();

		Map<String, Object> expected = new LinkedHashMap<>();
		expected.put("email", Arrays.asList("john.doe@example.com", "doe.john@example.com"));
		expected.put("name", Collections.singletonList("John Doe"));
		expected.put("age", Collections.singletonList(21));
		expected.put("website", Collections.singletonList("https://johndoe.com/"));
		expected.put("registered", Collections.singletonList(true));
		Instant registeredDate = Instant.ofEpochMilli(DateTime.parse("1970-01-01T00:00:00Z").getMillis());
		expected.put("registeredDate", Collections.singletonList(registeredDate));

		assertThat((String) principal.getFirstAttribute("name")).isEqualTo("John Doe");
		assertThat(principal.getAttributes()).isEqualTo(expected);
	}

	@Test
	public void authenticateWhenAttributeValueMarshallerConfiguredThenUses() throws Exception {
		Response response = response();
		Assertion assertion = assertion();
		List<AttributeStatement> attributes = attributeStatements();
		assertion.getAttributeStatements().addAll(attributes);
		signed(assertion, assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID);
		response.getAssertions().add(assertion);
		Saml2AuthenticationToken token = token(response, relyingPartyVerifyingCredential());

		Element attributeElement = element("<element>value</element>");
		Marshaller marshaller = mock(Marshaller.class);
		when(marshaller.marshall(any(XMLObject.class))).thenReturn(attributeElement);

		try {
			XMLObjectProviderRegistrySupport.getMarshallerFactory().registerMarshaller(AttributeValue.DEFAULT_ELEMENT_NAME, marshaller);
			this.provider.authenticate(token);
			verify(marshaller, atLeastOnce()).marshall(any(XMLObject.class));
		} finally {
			XMLObjectProviderRegistrySupport.getMarshallerFactory().deregisterMarshaller(AttributeValue.DEFAULT_ELEMENT_NAME);
		}
	}

	@Test
	public void authenticateWhenEncryptedAssertionWithoutSignatureThenItFails() throws Exception {
		this.exception.expect(authenticationMatcher(Saml2ErrorCodes.INVALID_SIGNATURE));

		Response response = response();
		EncryptedAssertion encryptedAssertion = encrypted(assertion(), assertingPartyEncryptingCredential());
		response.getEncryptedAssertions().add(encryptedAssertion);
		Saml2AuthenticationToken token = token(response, relyingPartyDecryptingCredential());
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenEncryptedAssertionWithSignatureThenItSucceeds() throws Exception {
		Response response = response();
		Assertion assertion = signed(assertion(), assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID);
		EncryptedAssertion encryptedAssertion = encrypted(assertion, assertingPartyEncryptingCredential());
		response.getEncryptedAssertions().add(encryptedAssertion);
		Saml2AuthenticationToken token = token(response, relyingPartyVerifyingCredential(), relyingPartyDecryptingCredential());
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenEncryptedAssertionWithResponseSignatureThenItSucceeds() throws Exception {
		Response response = response();
		EncryptedAssertion encryptedAssertion = encrypted(assertion(), assertingPartyEncryptingCredential());
		response.getEncryptedAssertions().add(encryptedAssertion);
		signed(response, assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID);
		Saml2AuthenticationToken token = token(response, relyingPartyVerifyingCredential(), relyingPartyDecryptingCredential());
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenEncryptedNameIdWithSignatureThenItSucceeds() throws Exception {
		Response response = response();
		Assertion assertion = assertion();
		NameID nameId = assertion.getSubject().getNameID();
		EncryptedID encryptedID = encrypted(nameId, assertingPartyEncryptingCredential());
		assertion.getSubject().setNameID(null);
		assertion.getSubject().setEncryptedID(encryptedID);
		response.getAssertions().add(assertion);
		signed(assertion, assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID);
		Saml2AuthenticationToken token = token(response, relyingPartyVerifyingCredential(), relyingPartyDecryptingCredential());
		this.provider.authenticate(token);
	}


	@Test
	public void authenticateWhenDecryptionKeysAreMissingThenThrowAuthenticationException() throws Exception {
		this.exception.expect(
				authenticationMatcher(Saml2ErrorCodes.DECRYPTION_ERROR, "No valid decryption credentials found.")
		);

		Response response = response();
		EncryptedAssertion encryptedAssertion = encrypted(assertion(), assertingPartyEncryptingCredential());
		response.getEncryptedAssertions().add(encryptedAssertion);
		Saml2AuthenticationToken token = token(serialize(response), relyingPartyVerifyingCredential());
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenDecryptionKeysAreWrongThenThrowAuthenticationException() throws Exception {
		this.exception.expect(
				authenticationMatcher(Saml2ErrorCodes.DECRYPTION_ERROR, "Failed to decrypt EncryptedData")
		);

		Response response = response();
		EncryptedAssertion encryptedAssertion = encrypted(assertion(), assertingPartyEncryptingCredential());
		response.getEncryptedAssertions().add(encryptedAssertion);
		Saml2AuthenticationToken token = token(serialize(response), assertingPartyPrivateCredential());
		this.provider.authenticate(token);
	}

	@Test
	public void writeObjectWhenTypeIsSaml2AuthenticationThenNoException() throws IOException {
		Response response = response();
		Assertion assertion = signed(assertion(), assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID);
		EncryptedAssertion encryptedAssertion = encrypted(assertion, assertingPartyEncryptingCredential());
		response.getEncryptedAssertions().add(encryptedAssertion);
		Saml2AuthenticationToken token = token(response, relyingPartyVerifyingCredential(), relyingPartyDecryptingCredential());
		Saml2Authentication authentication = (Saml2Authentication) this.provider.authenticate(token);

		// the following code will throw an exception if authentication isn't serializable
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream(1024);
		ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteStream);
		objectOutputStream.writeObject(authentication);
		objectOutputStream.flush();
	}

	private String serialize(XMLObject object) {
		try {
			Marshaller marshaller = getMarshallerFactory().getMarshaller(object);
			Element element = marshaller.marshall(object);
			return SerializeSupport.nodeToString(element);
		} catch (MarshallingException e) {
			throw new Saml2Exception(e);
		}
	}

	private Matcher<Saml2AuthenticationException> authenticationMatcher(String code) {
		return authenticationMatcher(code, null);
	}

	private Matcher<Saml2AuthenticationException> authenticationMatcher(String code, String description) {
		return new BaseMatcher<Saml2AuthenticationException>() {
			@Override
			public boolean matches(Object item) {
				if (!(item instanceof Saml2AuthenticationException)) {
					return false;
				}
				Saml2AuthenticationException ex = (Saml2AuthenticationException) item;
				if (!code.equals(ex.getError().getErrorCode())) {
					return false;
				}
				if (hasText(description)) {
					if (!description.equals(ex.getError().getDescription())) {
						return false;
					}
				}
				return true;
			}

			@Override
			public void describeTo(Description desc) {
				String excepting = "Saml2AuthenticationException[code="+code+"; description="+description+"]";
				desc.appendText(excepting);

			}
		};
	}

	private Saml2AuthenticationToken token(Response response, Saml2X509Credential... credentials) {
		String payload = serialize(response);
		return token(payload, credentials);
	}

	private Saml2AuthenticationToken token(String payload, Saml2X509Credential... credentials) {
		return new Saml2AuthenticationToken(payload,
				DESTINATION, ASSERTING_PARTY_ENTITY_ID, RELYING_PARTY_ENTITY_ID, Arrays.asList(credentials));
	}

	private static Element element(String xml) throws Exception {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		DocumentBuilder builder = factory.newDocumentBuilder();
		Document doc = builder.parse(new InputSource(new StringReader(xml)));
		return doc.getDocumentElement();
	}
}
