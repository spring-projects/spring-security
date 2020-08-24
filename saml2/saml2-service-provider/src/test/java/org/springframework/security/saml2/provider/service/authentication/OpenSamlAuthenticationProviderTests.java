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
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;

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
import org.opensaml.saml.common.assertion.ValidationContext;
import org.opensaml.saml.saml2.assertion.SAML2AssertionValidationParameters;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.EncryptedID;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.OneTimeUse;
import org.opensaml.saml.saml2.core.Response;
import org.w3c.dom.Element;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ResponseValidatorResult;
import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.security.saml2.credentials.TestSaml2X509Credentials;
import org.springframework.util.StringUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

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

	private Saml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal("name",
			Collections.emptyMap());

	private Saml2Authentication authentication = new Saml2Authentication(this.principal, "response",
			Collections.emptyList());

	@Rule
	public ExpectedException exception = ExpectedException.none();

	@Test
	public void supportsWhenSaml2AuthenticationTokenThenReturnTrue() {
		assertThat(this.provider.supports(Saml2AuthenticationToken.class))
				.withFailMessage(
						OpenSamlAuthenticationProvider.class + "should support " + Saml2AuthenticationToken.class)
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
		Assertion assertion = (Assertion) XMLObjectProviderRegistrySupport.getBuilderFactory()
				.getBuilder(Assertion.DEFAULT_ELEMENT_NAME).buildObject(Assertion.DEFAULT_ELEMENT_NAME);
		this.provider
				.authenticate(token(serialize(assertion), TestSaml2X509Credentials.relyingPartyVerifyingCredential()));
	}

	@Test
	public void authenticateWhenXmlErrorThenThrowAuthenticationException() {
		this.exception.expect(authenticationMatcher(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA));
		Saml2AuthenticationToken token = token("invalid xml",
				TestSaml2X509Credentials.relyingPartyVerifyingCredential());
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenInvalidDestinationThenThrowAuthenticationException() {
		this.exception.expect(authenticationMatcher(Saml2ErrorCodes.INVALID_DESTINATION));
		Response response = TestOpenSamlObjects.response(DESTINATION + "invalid", ASSERTING_PARTY_ENTITY_ID);
		response.getAssertions().add(TestOpenSamlObjects.assertion());
		TestOpenSamlObjects.signed(response, TestSaml2X509Credentials.assertingPartySigningCredential(),
				RELYING_PARTY_ENTITY_ID);
		Saml2AuthenticationToken token = token(response, TestSaml2X509Credentials.relyingPartyVerifyingCredential());
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenNoAssertionsPresentThenThrowAuthenticationException() {
		this.exception.expect(
				authenticationMatcher(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA, "No assertions found in response."));
		Saml2AuthenticationToken token = token(TestOpenSamlObjects.response(),
				TestSaml2X509Credentials.assertingPartySigningCredential());
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenInvalidSignatureOnAssertionThenThrowAuthenticationException() {
		this.exception.expect(authenticationMatcher(Saml2ErrorCodes.INVALID_SIGNATURE));
		Response response = TestOpenSamlObjects.response();
		response.getAssertions().add(TestOpenSamlObjects.assertion());
		Saml2AuthenticationToken token = token(response, TestSaml2X509Credentials.relyingPartyVerifyingCredential());
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenOpenSAMLValidationErrorThenThrowAuthenticationException() throws Exception {
		this.exception.expect(authenticationMatcher(Saml2ErrorCodes.INVALID_ASSERTION));
		Response response = TestOpenSamlObjects.response();
		Assertion assertion = TestOpenSamlObjects.assertion();
		assertion.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData()
				.setNotOnOrAfter(DateTime.now().minus(Duration.standardDays(3)));
		TestOpenSamlObjects.signed(assertion, TestSaml2X509Credentials.assertingPartySigningCredential(),
				RELYING_PARTY_ENTITY_ID);
		response.getAssertions().add(assertion);
		Saml2AuthenticationToken token = token(response, TestSaml2X509Credentials.relyingPartyVerifyingCredential());
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenMissingSubjectThenThrowAuthenticationException() {
		this.exception.expect(authenticationMatcher(Saml2ErrorCodes.SUBJECT_NOT_FOUND));
		Response response = TestOpenSamlObjects.response();
		Assertion assertion = TestOpenSamlObjects.assertion();
		assertion.setSubject(null);
		TestOpenSamlObjects.signed(assertion, TestSaml2X509Credentials.assertingPartySigningCredential(),
				RELYING_PARTY_ENTITY_ID);
		response.getAssertions().add(assertion);
		Saml2AuthenticationToken token = token(response, TestSaml2X509Credentials.relyingPartyVerifyingCredential());
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenUsernameMissingThenThrowAuthenticationException() throws Exception {
		this.exception.expect(authenticationMatcher(Saml2ErrorCodes.SUBJECT_NOT_FOUND));
		Response response = TestOpenSamlObjects.response();
		Assertion assertion = TestOpenSamlObjects.assertion();
		assertion.getSubject().getNameID().setValue(null);
		TestOpenSamlObjects.signed(assertion, TestSaml2X509Credentials.assertingPartySigningCredential(),
				RELYING_PARTY_ENTITY_ID);
		response.getAssertions().add(assertion);
		Saml2AuthenticationToken token = token(response, TestSaml2X509Credentials.relyingPartyVerifyingCredential());
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenAssertionContainsValidationAddressThenItSucceeds() throws Exception {
		Response response = TestOpenSamlObjects.response();
		Assertion assertion = TestOpenSamlObjects.assertion();
		assertion.getSubject().getSubjectConfirmations()
				.forEach((sc) -> sc.getSubjectConfirmationData().setAddress("10.10.10.10"));
		TestOpenSamlObjects.signed(assertion, TestSaml2X509Credentials.assertingPartySigningCredential(),
				RELYING_PARTY_ENTITY_ID);
		response.getAssertions().add(assertion);
		Saml2AuthenticationToken token = token(response, TestSaml2X509Credentials.relyingPartyVerifyingCredential());
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenAssertionContainsAttributesThenItSucceeds() {
		Response response = TestOpenSamlObjects.response();
		Assertion assertion = TestOpenSamlObjects.assertion();
		List<AttributeStatement> attributes = TestOpenSamlObjects.attributeStatements();
		assertion.getAttributeStatements().addAll(attributes);
		TestOpenSamlObjects.signed(assertion, TestSaml2X509Credentials.assertingPartySigningCredential(),
				RELYING_PARTY_ENTITY_ID);
		response.getAssertions().add(assertion);
		Saml2AuthenticationToken token = token(response, TestSaml2X509Credentials.relyingPartyVerifyingCredential());
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
	public void authenticateWhenEncryptedAssertionWithoutSignatureThenItFails() throws Exception {
		this.exception.expect(authenticationMatcher(Saml2ErrorCodes.INVALID_SIGNATURE));
		Response response = TestOpenSamlObjects.response();
		EncryptedAssertion encryptedAssertion = TestOpenSamlObjects.encrypted(TestOpenSamlObjects.assertion(),
				TestSaml2X509Credentials.assertingPartyEncryptingCredential());
		response.getEncryptedAssertions().add(encryptedAssertion);
		Saml2AuthenticationToken token = token(response, TestSaml2X509Credentials.relyingPartyDecryptingCredential());
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenEncryptedAssertionWithSignatureThenItSucceeds() throws Exception {
		Response response = TestOpenSamlObjects.response();
		Assertion assertion = TestOpenSamlObjects.signed(TestOpenSamlObjects.assertion(),
				TestSaml2X509Credentials.assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID);
		EncryptedAssertion encryptedAssertion = TestOpenSamlObjects.encrypted(assertion,
				TestSaml2X509Credentials.assertingPartyEncryptingCredential());
		response.getEncryptedAssertions().add(encryptedAssertion);
		Saml2AuthenticationToken token = token(response, TestSaml2X509Credentials.relyingPartyVerifyingCredential(),
				TestSaml2X509Credentials.relyingPartyDecryptingCredential());
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenEncryptedAssertionWithResponseSignatureThenItSucceeds() throws Exception {
		Response response = TestOpenSamlObjects.response();
		EncryptedAssertion encryptedAssertion = TestOpenSamlObjects.encrypted(TestOpenSamlObjects.assertion(),
				TestSaml2X509Credentials.assertingPartyEncryptingCredential());
		response.getEncryptedAssertions().add(encryptedAssertion);
		TestOpenSamlObjects.signed(response, TestSaml2X509Credentials.assertingPartySigningCredential(),
				RELYING_PARTY_ENTITY_ID);
		Saml2AuthenticationToken token = token(response, TestSaml2X509Credentials.relyingPartyVerifyingCredential(),
				TestSaml2X509Credentials.relyingPartyDecryptingCredential());
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenEncryptedNameIdWithSignatureThenItSucceeds() throws Exception {
		Response response = TestOpenSamlObjects.response();
		Assertion assertion = TestOpenSamlObjects.assertion();
		NameID nameId = assertion.getSubject().getNameID();
		EncryptedID encryptedID = TestOpenSamlObjects.encrypted(nameId,
				TestSaml2X509Credentials.assertingPartyEncryptingCredential());
		assertion.getSubject().setNameID(null);
		assertion.getSubject().setEncryptedID(encryptedID);
		response.getAssertions().add(assertion);
		TestOpenSamlObjects.signed(assertion, TestSaml2X509Credentials.assertingPartySigningCredential(),
				RELYING_PARTY_ENTITY_ID);
		Saml2AuthenticationToken token = token(response, TestSaml2X509Credentials.relyingPartyVerifyingCredential(),
				TestSaml2X509Credentials.relyingPartyDecryptingCredential());
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenDecryptionKeysAreMissingThenThrowAuthenticationException() throws Exception {
		this.exception
				.expect(authenticationMatcher(Saml2ErrorCodes.DECRYPTION_ERROR, "Failed to decrypt EncryptedData"));
		Response response = TestOpenSamlObjects.response();
		EncryptedAssertion encryptedAssertion = TestOpenSamlObjects.encrypted(TestOpenSamlObjects.assertion(),
				TestSaml2X509Credentials.assertingPartyEncryptingCredential());
		response.getEncryptedAssertions().add(encryptedAssertion);
		Saml2AuthenticationToken token = token(serialize(response),
				TestSaml2X509Credentials.relyingPartyVerifyingCredential());
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenDecryptionKeysAreWrongThenThrowAuthenticationException() throws Exception {
		this.exception
				.expect(authenticationMatcher(Saml2ErrorCodes.DECRYPTION_ERROR, "Failed to decrypt EncryptedData"));
		Response response = TestOpenSamlObjects.response();
		EncryptedAssertion encryptedAssertion = TestOpenSamlObjects.encrypted(TestOpenSamlObjects.assertion(),
				TestSaml2X509Credentials.assertingPartyEncryptingCredential());
		response.getEncryptedAssertions().add(encryptedAssertion);
		Saml2AuthenticationToken token = token(serialize(response),
				TestSaml2X509Credentials.assertingPartyPrivateCredential());
		this.provider.authenticate(token);
	}

	@Test
	public void writeObjectWhenTypeIsSaml2AuthenticationThenNoException() throws IOException {
		Response response = TestOpenSamlObjects.response();
		Assertion assertion = TestOpenSamlObjects.signed(TestOpenSamlObjects.assertion(),
				TestSaml2X509Credentials.assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID);
		EncryptedAssertion encryptedAssertion = TestOpenSamlObjects.encrypted(assertion,
				TestSaml2X509Credentials.assertingPartyEncryptingCredential());
		response.getEncryptedAssertions().add(encryptedAssertion);
		Saml2AuthenticationToken token = token(response, TestSaml2X509Credentials.relyingPartyVerifyingCredential(),
				TestSaml2X509Credentials.relyingPartyDecryptingCredential());
		Saml2Authentication authentication = (Saml2Authentication) this.provider.authenticate(token);
		// the following code will throw an exception if authentication isn't serializable
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream(1024);
		ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteStream);
		objectOutputStream.writeObject(authentication);
		objectOutputStream.flush();
	}

	@Test
	public void createDefaultAssertionValidatorWhenAssertionThenValidates() {
		Response response = TestOpenSamlObjects.signedResponseWithOneAssertion();
		Assertion assertion = response.getAssertions().get(0);
		OpenSamlAuthenticationProvider.AssertionToken assertionToken = new OpenSamlAuthenticationProvider.AssertionToken(
				assertion, token());
		assertThat(OpenSamlAuthenticationProvider.createDefaultAssertionValidator().convert(assertionToken).hasErrors())
				.isFalse();
	}

	@Test
	public void authenticateWhenDelegatingToDefaultAssertionValidatorThenUses() {
		OpenSamlAuthenticationProvider provider = new OpenSamlAuthenticationProvider();
		// @formatter:off
		provider.setAssertionValidator((assertionToken) -> OpenSamlAuthenticationProvider
				.createDefaultAssertionValidator((token) -> new ValidationContext())
				.convert(assertionToken)
				.concat(new Saml2Error("wrong error", "wrong error"))
		);
		// @formatter:on
		Response response = TestOpenSamlObjects.response();
		Assertion assertion = TestOpenSamlObjects.assertion();
		OneTimeUse oneTimeUse = build(OneTimeUse.DEFAULT_ELEMENT_NAME);
		assertion.getConditions().getConditions().add(oneTimeUse);
		response.getAssertions().add(assertion);
		TestOpenSamlObjects.signed(response, TestSaml2X509Credentials.assertingPartySigningCredential(),
				ASSERTING_PARTY_ENTITY_ID);
		Saml2AuthenticationToken token = token(response, TestSaml2X509Credentials.relyingPartyVerifyingCredential());
		// @formatter:off
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> provider.authenticate(token)).isInstanceOf(Saml2AuthenticationException.class)
				.satisfies((error) -> assertThat(error.getSaml2Error().getErrorCode()).isEqualTo(Saml2ErrorCodes.INVALID_ASSERTION));
		// @formatter:on
	}

	@Test
	public void authenticateWhenCustomAssertionValidatorThenUses() {
		Converter<OpenSamlAuthenticationProvider.AssertionToken, Saml2ResponseValidatorResult> validator = mock(
				Converter.class);
		OpenSamlAuthenticationProvider provider = new OpenSamlAuthenticationProvider();
		// @formatter:off
		provider.setAssertionValidator((assertionToken) -> OpenSamlAuthenticationProvider.createDefaultAssertionValidator()
				.convert(assertionToken)
				.concat(validator.convert(assertionToken))
		);
		// @formatter:on
		Response response = TestOpenSamlObjects.response();
		Assertion assertion = TestOpenSamlObjects.assertion();
		response.getAssertions().add(assertion);
		TestOpenSamlObjects.signed(response, TestSaml2X509Credentials.assertingPartySigningCredential(),
				ASSERTING_PARTY_ENTITY_ID);
		Saml2AuthenticationToken token = token(response, TestSaml2X509Credentials.relyingPartyVerifyingCredential());
		given(validator.convert(any(OpenSamlAuthenticationProvider.AssertionToken.class)))
				.willReturn(Saml2ResponseValidatorResult.success());
		provider.authenticate(token);
		verify(validator).convert(any(OpenSamlAuthenticationProvider.AssertionToken.class));
	}

	@Test
	public void authenticateWhenDefaultConditionValidatorNotUsedThenSignatureStillChecked() {
		OpenSamlAuthenticationProvider provider = new OpenSamlAuthenticationProvider();
		provider.setAssertionValidator((assertionToken) -> Saml2ResponseValidatorResult.success());
		Response response = TestOpenSamlObjects.response();
		Assertion assertion = TestOpenSamlObjects.assertion();
		TestOpenSamlObjects.signed(assertion, TestSaml2X509Credentials.relyingPartyDecryptingCredential(),
				RELYING_PARTY_ENTITY_ID); // broken
		// signature
		response.getAssertions().add(assertion);
		TestOpenSamlObjects.signed(response, TestSaml2X509Credentials.assertingPartySigningCredential(),
				ASSERTING_PARTY_ENTITY_ID);
		Saml2AuthenticationToken token = token(response, TestSaml2X509Credentials.relyingPartyVerifyingCredential());
		// @formatter:off
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> provider.authenticate(token))
				.satisfies((error) -> assertThat(error.getSaml2Error().getErrorCode()).isEqualTo(Saml2ErrorCodes.INVALID_SIGNATURE));
		// @formatter:on
	}

	@Test
	public void authenticateWhenValidationContextCustomizedThenUsers() {
		Map<String, Object> parameters = new HashMap<>();
		parameters.put(SAML2AssertionValidationParameters.SC_VALID_RECIPIENTS, Collections.singleton("blah"));
		ValidationContext context = mock(ValidationContext.class);
		given(context.getStaticParameters()).willReturn(parameters);
		OpenSamlAuthenticationProvider provider = new OpenSamlAuthenticationProvider();
		provider.setAssertionValidator(
				OpenSamlAuthenticationProvider.createDefaultAssertionValidator((assertionToken) -> context));
		Response response = TestOpenSamlObjects.response();
		Assertion assertion = TestOpenSamlObjects.assertion();
		response.getAssertions().add(assertion);
		TestOpenSamlObjects.signed(response, TestSaml2X509Credentials.assertingPartySigningCredential(),
				ASSERTING_PARTY_ENTITY_ID);
		Saml2AuthenticationToken token = token(response, TestSaml2X509Credentials.relyingPartyVerifyingCredential());
		// @formatter:off
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> provider.authenticate(token)).isInstanceOf(Saml2AuthenticationException.class)
				.satisfies((error) -> assertThat(error).hasMessageContaining("Invalid assertion"));
		// @formatter:on
		verify(context, atLeastOnce()).getStaticParameters();
	}

	@Test
	public void setAssertionValidatorWhenNullThenIllegalArgument() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.provider.setAssertionValidator(null));
		// @formatter:on
	}

	@Test
	public void createDefaultResponseAuthenticationConverterWhenResponseThenConverts() {
		Response response = TestOpenSamlObjects.signedResponseWithOneAssertion();
		Saml2AuthenticationToken token = token(response, TestSaml2X509Credentials.relyingPartyVerifyingCredential());
		OpenSamlAuthenticationProvider.ResponseToken responseToken = new OpenSamlAuthenticationProvider.ResponseToken(
				response, token);
		Saml2Authentication authentication = OpenSamlAuthenticationProvider
				.createDefaultResponseAuthenticationConverter().convert(responseToken);
		assertThat(authentication.getName()).isEqualTo("test@saml.user");
	}

	@Test
	public void authenticateWhenResponseAuthenticationConverterConfiguredThenUses() {
		Converter<OpenSamlAuthenticationProvider.ResponseToken, Saml2Authentication> authenticationConverter = mock(
				Converter.class);
		OpenSamlAuthenticationProvider provider = new OpenSamlAuthenticationProvider();
		provider.setResponseAuthenticationConverter(authenticationConverter);
		Response response = TestOpenSamlObjects.signedResponseWithOneAssertion();
		Saml2AuthenticationToken token = token(response, TestSaml2X509Credentials.relyingPartyVerifyingCredential());
		provider.authenticate(token);
		verify(authenticationConverter).convert(any());
	}

	@Test
	public void setResponseAuthenticationConverterWhenNullThenIllegalArgument() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.provider.setResponseAuthenticationConverter(null));
		// @formatter:on
	}

	private <T extends XMLObject> T build(QName qName) {
		return (T) XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(qName).buildObject(qName);
	}

	private String serialize(XMLObject object) {
		try {
			Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
			Element element = marshaller.marshall(object);
			return SerializeSupport.nodeToString(element);
		}
		catch (MarshallingException ex) {
			throw new Saml2Exception(ex);
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
				if (StringUtils.hasText(description)) {
					if (!description.equals(ex.getError().getDescription())) {
						return false;
					}
				}
				return true;
			}

			@Override
			public void describeTo(Description desc) {
				String excepting = "Saml2AuthenticationException[code=" + code + "; description=" + description + "]";
				desc.appendText(excepting);
			}
		};
	}

	private Saml2AuthenticationToken token() {
		return token(TestOpenSamlObjects.response(), TestSaml2X509Credentials.relyingPartyVerifyingCredential());
	}

	private Saml2AuthenticationToken token(Response response, Saml2X509Credential... credentials) {
		String payload = serialize(response);
		return token(payload, credentials);
	}

	private Saml2AuthenticationToken token(String payload, Saml2X509Credential... credentials) {
		return new Saml2AuthenticationToken(payload, DESTINATION, ASSERTING_PARTY_ENTITY_ID, RELYING_PARTY_ENTITY_ID,
				Arrays.asList(credentials));
	}

}
