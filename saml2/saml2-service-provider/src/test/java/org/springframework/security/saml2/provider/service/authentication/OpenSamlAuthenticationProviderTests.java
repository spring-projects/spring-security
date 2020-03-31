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
import java.util.Arrays;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.EncryptedID;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;

import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.credentials.Saml2X509Credential;

import static org.springframework.security.saml2.provider.service.authentication.TestOpenSamlObjects.assertion;
import static org.springframework.security.saml2.provider.service.authentication.TestOpenSamlObjects.encrypted;
import static org.springframework.security.saml2.provider.service.authentication.TestOpenSamlObjects.response;
import static org.springframework.security.saml2.provider.service.authentication.TestOpenSamlObjects.signed;
import static org.springframework.security.saml2.provider.service.authentication.TestSaml2X509Credentials.assertingPartyEncryptingCredential;
import static org.springframework.security.saml2.provider.service.authentication.TestSaml2X509Credentials.assertingPartyPrivateCredential;
import static org.springframework.security.saml2.provider.service.authentication.TestSaml2X509Credentials.assertingPartySigningCredential;
import static org.springframework.security.saml2.provider.service.authentication.TestSaml2X509Credentials.relyingPartyDecryptingCredential;
import static org.springframework.security.saml2.provider.service.authentication.TestSaml2X509Credentials.relyingPartyVerifyingCredential;
import static org.springframework.test.util.AssertionErrors.assertTrue;
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
	private OpenSamlImplementation saml = OpenSamlImplementation.getInstance();


	@Rule
	public ExpectedException exception = ExpectedException.none();

	@Test
	public void supportsWhenSaml2AuthenticationTokenThenReturnTrue() {

		assertTrue(
				OpenSamlAuthenticationProvider.class + "should support " + Saml2AuthenticationToken.class,
				this.provider.supports(Saml2AuthenticationToken.class)
		);
	}

	@Test
	public void supportsWhenNotSaml2AuthenticationTokenThenReturnFalse() {
		assertTrue(
				OpenSamlAuthenticationProvider.class + "should not support " + Authentication.class,
				!this.provider.supports(Authentication.class)
		);
	}

	@Test
	public void authenticateWhenUnknownDataClassThenThrowAuthenticationException() {
		this.exception.expect(authenticationMatcher(Saml2ErrorCodes.UNKNOWN_RESPONSE_CLASS));

		Assertion assertion = this.saml.buildSamlObject(Assertion.DEFAULT_ELEMENT_NAME);
		this.provider.authenticate(token(this.saml.serialize(assertion)));
	}

	@Test
	public void authenticateWhenXmlErrorThenThrowAuthenticationException() {
		this.exception.expect(authenticationMatcher(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA));

		Saml2AuthenticationToken token = token("invalid xml");
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
		Saml2AuthenticationToken token = token(response);
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
		this.exception.expect(authenticationMatcher(Saml2ErrorCodes.USERNAME_NOT_FOUND));

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
		Saml2AuthenticationToken token = token(this.saml.serialize(response));
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
		Saml2AuthenticationToken token = token(this.saml.serialize(response), assertingPartyPrivateCredential());
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
		String payload = this.saml.serialize(response);
		return token(payload, credentials);
	}

	private Saml2AuthenticationToken token(String payload, Saml2X509Credential... credentials) {
		return new Saml2AuthenticationToken(payload,
				DESTINATION, ASSERTING_PARTY_ENTITY_ID, RELYING_PARTY_ENTITY_ID, Arrays.asList(credentials));
	}
}
