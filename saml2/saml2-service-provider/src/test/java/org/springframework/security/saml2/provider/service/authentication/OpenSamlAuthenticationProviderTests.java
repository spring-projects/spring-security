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

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.EncryptedID;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;

import org.springframework.security.core.Authentication;

import static java.util.Collections.emptyList;
import static org.springframework.security.saml2.provider.service.authentication.Saml2CryptoTestSupport.encryptAssertion;
import static org.springframework.security.saml2.provider.service.authentication.Saml2CryptoTestSupport.encryptNameId;
import static org.springframework.security.saml2.provider.service.authentication.Saml2CryptoTestSupport.signXmlObject;
import static org.springframework.security.saml2.provider.service.authentication.TestSaml2AuthenticationObjects.assertion;
import static org.springframework.security.saml2.provider.service.authentication.TestSaml2AuthenticationObjects.response;
import static org.springframework.security.saml2.provider.service.authentication.TestSaml2X509Credentials.assertingPartyCredentials;
import static org.springframework.security.saml2.provider.service.authentication.TestSaml2X509Credentials.relyingPartyCredentials;
import static org.springframework.test.util.AssertionErrors.assertTrue;
import static org.springframework.util.StringUtils.hasText;

public class OpenSamlAuthenticationProviderTests {

	private static String username = "test@saml.user";
	private static String recipientUri = "https://localhost/login/saml2/sso/idp-alias";
	private static String recipientEntityId = "https://localhost/saml2/service-provider-metadata/idp-alias";
	private static String idpEntityId = "https://some.idp.test/saml2/idp";

	private OpenSamlAuthenticationProvider provider;
	private OpenSamlImplementation saml;
	private Saml2AuthenticationToken token;

	@Rule
	public ExpectedException exception = ExpectedException.none();

	@Before
	public void setup() {
		saml = OpenSamlImplementation.getInstance();
		provider = new OpenSamlAuthenticationProvider();
		token = new Saml2AuthenticationToken(
				"responseXml",
				recipientUri,
				idpEntityId,
				recipientEntityId,
				relyingPartyCredentials()
		);
	}

	@Test
	public void supportsWhenSaml2AuthenticationTokenThenReturnTrue() {

		assertTrue(
				OpenSamlAuthenticationProvider.class + "should support " + token.getClass(),
				provider.supports(token.getClass())
		);
	}

	@Test
	public void supportsWhenNotSaml2AuthenticationTokenThenReturnFalse() {
		assertTrue(
				OpenSamlAuthenticationProvider.class + "should not support " + Authentication.class,
				!provider.supports(Authentication.class)
		);
	}

	@Test
	public void authenticateWhenUnknownDataClassThenThrowAuthenticationException() {
		Assertion assertion = defaultAssertion();
		token = responseXml(assertion);
		exception.expect(authenticationMatcher(Saml2ErrorCodes.UNKNOWN_RESPONSE_CLASS));
		provider.authenticate(token);
	}

	@Test
	public void authenticateWhenXmlErrorThenThrowAuthenticationException() {
		token = new Saml2AuthenticationToken(
				"invalid xml string",
				recipientUri,
				idpEntityId,
				recipientEntityId,
				relyingPartyCredentials()
		);
		exception.expect(authenticationMatcher(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA));
		provider.authenticate(token);
	}

	@Test
	public void authenticateWhenInvalidDestinationThenThrowAuthenticationException() {
		Response response = response(recipientUri + "invalid", idpEntityId);
		token = responseXml(response);
		exception.expect(authenticationMatcher(Saml2ErrorCodes.INVALID_DESTINATION));
		provider.authenticate(token);
	}

	@Test
	public void authenticateWhenNoAssertionsPresentThenThrowAuthenticationException() {
		Response response = response(recipientUri, idpEntityId);
		token = responseXml(response);
		exception.expect(
				authenticationMatcher(
						Saml2ErrorCodes.MALFORMED_RESPONSE_DATA,
						"No assertions found in response."
				)
		);
		provider.authenticate(token);
	}

	@Test
	public void authenticateWhenInvalidSignatureOnAssertionThenThrowAuthenticationException() {
		Response response = response(recipientUri, idpEntityId);
		Assertion assertion = defaultAssertion();
		response.getAssertions().add(assertion);
		token = responseXml(response);
		exception.expect(
				authenticationMatcher(
						Saml2ErrorCodes.INVALID_SIGNATURE
				)
		);
		provider.authenticate(token);
	}

	@Test
	public void authenticateWhenOpenSAMLValidationErrorThenThrowAuthenticationException() throws Exception {
		Response response = response(recipientUri, idpEntityId);
		Assertion assertion = defaultAssertion();
		assertion
				.getSubject()
				.getSubjectConfirmations()
				.get(0)
				.getSubjectConfirmationData()
				.setNotOnOrAfter(DateTime.now().minus(Duration.standardDays(3)));
		signXmlObject(
				assertion,
				assertingPartyCredentials(),
				recipientEntityId
		);
		response.getAssertions().add(assertion);
		token = responseXml(response);

		exception.expect(
				authenticationMatcher(
						Saml2ErrorCodes.INVALID_ASSERTION
				)
		);
		provider.authenticate(token);
	}

	@Test
	public void authenticateWhenMissingSubjectThenThrowAuthenticationException()  {
		Response response = response(recipientUri, idpEntityId);
		Assertion assertion = defaultAssertion();
		assertion.setSubject(null);
		signXmlObject(
				assertion,
				assertingPartyCredentials(),
				recipientEntityId
		);
		response.getAssertions().add(assertion);
		token = responseXml(response);

		exception.expect(
				authenticationMatcher(
						Saml2ErrorCodes.SUBJECT_NOT_FOUND
				)
		);
		provider.authenticate(token);
	}

	@Test
	public void authenticateWhenUsernameMissingThenThrowAuthenticationException() throws Exception {
		Response response = response(recipientUri, idpEntityId);
		Assertion assertion = defaultAssertion();
		assertion
				.getSubject()
				.getNameID()
				.setValue(null);
		signXmlObject(
				assertion,
				assertingPartyCredentials(),
				recipientEntityId
		);
		response.getAssertions().add(assertion);
		token = responseXml(response);

		exception.expect(
				authenticationMatcher(
						Saml2ErrorCodes.USERNAME_NOT_FOUND
				)
		);
		provider.authenticate(token);
	}

	@Test
	public void authenticateWhenAssertionContainsValidationAddressThenItSucceeds() throws Exception {
		Response response = response(recipientUri, idpEntityId);
		Assertion assertion = defaultAssertion();
		assertion.getSubject().getSubjectConfirmations().forEach(
				sc -> sc.getSubjectConfirmationData().setAddress("10.10.10.10")
		);
		signXmlObject(
				assertion,
				assertingPartyCredentials(),
				recipientEntityId
		);
		response.getAssertions().add(assertion);
		token = responseXml(response);
		provider.authenticate(token);
	}

	@Test
	public void authenticateWhenEncryptedAssertionWithoutSignatureThenItFails() throws Exception {
		Response response = response(recipientUri, idpEntityId);
		Assertion assertion = defaultAssertion();
		EncryptedAssertion encryptedAssertion = encryptAssertion(assertion, assertingPartyCredentials());
		response.getEncryptedAssertions().add(encryptedAssertion);
		token = responseXml(response);
		exception.expect(
				authenticationMatcher(
						Saml2ErrorCodes.INVALID_SIGNATURE
				)
		);
		provider.authenticate(token);
	}

	@Test
	public void authenticateWhenEncryptedAssertionWithSignatureThenItSucceeds() throws Exception {
		Response response = response(recipientUri, idpEntityId);
		Assertion assertion = defaultAssertion();
		signXmlObject(
				assertion,
				assertingPartyCredentials(),
				recipientEntityId
		);
		EncryptedAssertion encryptedAssertion = encryptAssertion(assertion, assertingPartyCredentials());
		response.getEncryptedAssertions().add(encryptedAssertion);
		token = responseXml(response);
		provider.authenticate(token);
	}

	@Test
	public void authenticateWhenEncryptedAssertionWithResponseSignatureThenItSucceeds() throws Exception {
		Response response = response(recipientUri, idpEntityId);
		Assertion assertion = defaultAssertion();
		EncryptedAssertion encryptedAssertion = encryptAssertion(assertion, assertingPartyCredentials());
		response.getEncryptedAssertions().add(encryptedAssertion);
		signXmlObject(
				response,
				assertingPartyCredentials(),
				recipientEntityId
		);
		token = responseXml(response);
		provider.authenticate(token);
	}

	@Test
	public void authenticateWhenEncryptedNameIdWithSignatureThenItSucceeds() throws Exception {
		Response response = response(recipientUri, idpEntityId);
		Assertion assertion = defaultAssertion();
		NameID nameId = assertion.getSubject().getNameID();
		EncryptedID encryptedID = encryptNameId(nameId, assertingPartyCredentials());
		assertion.getSubject().setNameID(null);
		assertion.getSubject().setEncryptedID(encryptedID);
		signXmlObject(
				assertion,
				assertingPartyCredentials(),
				recipientEntityId
		);
		response.getAssertions().add(assertion);
		token = responseXml(response);
		provider.authenticate(token);
	}


	@Test
	public void authenticateWhenDecryptionKeysAreMissingThenThrowAuthenticationException() throws Exception {
		Response response = response(recipientUri, idpEntityId);
		Assertion assertion = defaultAssertion();
		EncryptedAssertion encryptedAssertion = encryptAssertion(assertion, assertingPartyCredentials());
		response.getEncryptedAssertions().add(encryptedAssertion);
		token = responseXml(response);

		token = new Saml2AuthenticationToken(
				token.getSaml2Response(),
				recipientUri,
				idpEntityId,
				recipientEntityId,
				emptyList()
		);

		exception.expect(
				authenticationMatcher(
						Saml2ErrorCodes.DECRYPTION_ERROR,
						"No valid decryption credentials found."
				)
		);
		provider.authenticate(token);
	}

	@Test
	public void authenticateWhenDecryptionKeysAreWrongThenThrowAuthenticationException() throws Exception {
		Response response = response(recipientUri, idpEntityId);
		Assertion assertion = defaultAssertion();
		EncryptedAssertion encryptedAssertion = encryptAssertion(assertion, assertingPartyCredentials());
		response.getEncryptedAssertions().add(encryptedAssertion);
		token = responseXml(response);

		token = new Saml2AuthenticationToken(
				token.getSaml2Response(),
				recipientUri,
				idpEntityId,
				recipientEntityId,
				assertingPartyCredentials()
		);

		exception.expect(
				authenticationMatcher(
						Saml2ErrorCodes.DECRYPTION_ERROR,
						"Failed to decrypt EncryptedData"
				)
		);
		provider.authenticate(token);
	}

	@Test
	public void writeObjectWhenTypeIsSaml2AuthenticationThenNoException() throws IOException {
		Response response = response(recipientUri, idpEntityId);
		Assertion assertion = defaultAssertion();
		signXmlObject(
				assertion,
				assertingPartyCredentials(),
				recipientEntityId
		);
		EncryptedAssertion encryptedAssertion = encryptAssertion(assertion, assertingPartyCredentials());
		response.getEncryptedAssertions().add(encryptedAssertion);
		token = responseXml(response);

		Saml2Authentication authentication = (Saml2Authentication) provider.authenticate(token);

		// the following code will throw an exception if authentication isn't serializable
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream(1024);
		ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteStream);
		objectOutputStream.writeObject(authentication);
		objectOutputStream.flush();
	}

	private Assertion defaultAssertion() {
		return assertion(
				username,
				idpEntityId,
				recipientEntityId,
				recipientUri
		);
	}

	private Saml2AuthenticationToken responseXml(XMLObject assertion) {
		String xml = saml.serialize(assertion);
		return new Saml2AuthenticationToken(
				xml,
				recipientUri,
				idpEntityId,
				recipientEntityId,
				relyingPartyCredentials()
		);

	}

	private BaseMatcher<Saml2AuthenticationException> authenticationMatcher(String code) {
		return authenticationMatcher(code, null);
	}

	private BaseMatcher<Saml2AuthenticationException> authenticationMatcher(String code, String description) {
		return new BaseMatcher<Saml2AuthenticationException>() {
			private Object value = null;

			@Override
			public boolean matches(Object item) {
				if (!(item instanceof Saml2AuthenticationException)) {
					value = item;
					return false;
				}
				Saml2AuthenticationException ex = (Saml2AuthenticationException) item;
				if (!code.equals(ex.getError().getErrorCode())) {
					value = item;
					return false;
				}
				if (hasText(description)) {
					if (!description.equals(ex.getError().getDescription())) {
						value = item;
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
}
