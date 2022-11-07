/*
 * Copyright 2002-2022 the original author or authors.
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
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import javax.xml.namespace.QName;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSDateTime;
import org.opensaml.core.xml.schema.impl.XSDateTimeBuilder;
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
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.OneTimeUse;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml.saml2.core.impl.EncryptedAssertionBuilder;
import org.opensaml.saml.saml2.core.impl.EncryptedIDBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;
import org.opensaml.xmlsec.encryption.impl.EncryptedDataBuilder;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.w3c.dom.Element;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ResponseValidatorResult;
import org.springframework.security.saml2.core.TestSaml2X509Credentials;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider.ResponseToken;
import org.springframework.security.saml2.provider.service.authentication.TestCustomOpenSamlObjects.CustomOpenSamlObject;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
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
 * Tests for {@link OpenSaml4AuthenticationProvider}
 *
 * @author Filip Hanik
 * @author Josh Cummings
 */
public class OpenSaml4AuthenticationProviderTests {

	private static String DESTINATION = "https://localhost/login/saml2/sso/idp-alias";

	private static String RELYING_PARTY_ENTITY_ID = "https://localhost/saml2/service-provider-metadata/idp-alias";

	private static String ASSERTING_PARTY_ENTITY_ID = "https://some.idp.test/saml2/idp";

	private OpenSaml4AuthenticationProvider provider = new OpenSaml4AuthenticationProvider();

	private Saml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal("name",
			Collections.emptyMap());

	private Saml2Authentication authentication = new Saml2Authentication(this.principal, "response",
			Collections.emptyList());

	@Test
	public void supportsWhenSaml2AuthenticationTokenThenReturnTrue() {
		assertThat(this.provider.supports(Saml2AuthenticationToken.class))
				.withFailMessage(
						OpenSaml4AuthenticationProvider.class + "should support " + Saml2AuthenticationToken.class)
				.isTrue();
	}

	@Test
	public void supportsWhenNotSaml2AuthenticationTokenThenReturnFalse() {
		assertThat(!this.provider.supports(Authentication.class))
				.withFailMessage(OpenSaml4AuthenticationProvider.class + "should not support " + Authentication.class)
				.isTrue();
	}

	@Test
	public void authenticateWhenUnknownDataClassThenThrowAuthenticationException() {
		Assertion assertion = (Assertion) XMLObjectProviderRegistrySupport.getBuilderFactory()
				.getBuilder(Assertion.DEFAULT_ELEMENT_NAME).buildObject(Assertion.DEFAULT_ELEMENT_NAME);
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(
						new Saml2AuthenticationToken(verifying(registration()).build(), serialize(assertion))))
				.satisfies(errorOf(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA));
	}

	@Test
	public void authenticateWhenXmlErrorThenThrowAuthenticationException() {
		Saml2AuthenticationToken token = new Saml2AuthenticationToken(verifying(registration()).build(), "invalid xml");
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.satisfies(errorOf(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA));
	}

	@Test
	public void authenticateWhenInvalidDestinationThenThrowAuthenticationException() {
		Response response = response(DESTINATION + "invalid", ASSERTING_PARTY_ENTITY_ID);
		response.getAssertions().add(assertion());
		Saml2AuthenticationToken token = token(signed(response), verifying(registration()));
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.satisfies(errorOf(Saml2ErrorCodes.INVALID_DESTINATION));
	}

	@Test
	public void authenticateWhenNoAssertionsPresentThenThrowAuthenticationException() {
		Saml2AuthenticationToken token = token();
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.satisfies(errorOf(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA, "No assertions found in response."));
	}

	@Test
	public void authenticateWhenInvalidSignatureOnAssertionThenThrowAuthenticationException() {
		Response response = response();
		response.getAssertions().add(assertion());
		Saml2AuthenticationToken token = token(response, verifying(registration()));
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.satisfies(errorOf(Saml2ErrorCodes.INVALID_SIGNATURE));
	}

	@Test
	public void authenticateWhenOpenSAMLValidationErrorThenThrowAuthenticationException() {
		Response response = response();
		Assertion assertion = assertion();
		assertion.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData()
				.setNotOnOrAfter(Instant.now().minus(Duration.ofDays(3)));
		response.getAssertions().add(signed(assertion));
		Saml2AuthenticationToken token = token(response, verifying(registration()));
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.satisfies(errorOf(Saml2ErrorCodes.INVALID_ASSERTION));
	}

	@Test
	public void authenticateWhenMissingSubjectThenThrowAuthenticationException() {
		Response response = response();
		Assertion assertion = assertion();
		assertion.setSubject(null);
		response.getAssertions().add(signed(assertion));
		Saml2AuthenticationToken token = token(response, verifying(registration()));
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.satisfies(errorOf(Saml2ErrorCodes.SUBJECT_NOT_FOUND));
	}

	@Test
	public void authenticateWhenUsernameMissingThenThrowAuthenticationException() {
		Response response = response();
		Assertion assertion = assertion();
		assertion.getSubject().getNameID().setValue(null);
		response.getAssertions().add(signed(assertion));
		Saml2AuthenticationToken token = token(response, verifying(registration()));
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.satisfies(errorOf(Saml2ErrorCodes.SUBJECT_NOT_FOUND));
	}

	@Test
	public void authenticateWhenAssertionContainsValidationAddressThenItSucceeds() {
		Response response = response();
		Assertion assertion = assertion();
		assertion.getSubject().getSubjectConfirmations()
				.forEach((sc) -> sc.getSubjectConfirmationData().setAddress("10.10.10.10"));
		response.getAssertions().add(signed(assertion));
		Saml2AuthenticationToken token = token(response, verifying(registration()));
		this.provider.authenticate(token);
	}

	@Test
	public void evaluateInResponseToSucceedsWhenInResponseToInResponseAndAssertionsMatchRequestID() {
		Response response = response();
		response.setInResponseTo("SAML2");
		response.getAssertions().add(signed(assertion("SAML2")));
		response.getAssertions().add(signed(assertion("SAML2")));
		AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mockedStoredAuthenticationRequest("SAML2",
				Saml2MessageBinding.POST, false);
		Saml2AuthenticationToken token = token(response, verifying(registration()), mockAuthenticationRequest);
		this.provider.authenticate(token);
	}

	@Test
	public void evaluateInResponseToSucceedsWhenInResponseToInAssertionOnlyMatchRequestID() {
		Response response = response();
		response.getAssertions().add(signed(assertion()));
		response.getAssertions().add(signed(assertion("SAML2")));
		AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mockedStoredAuthenticationRequest("SAML2",
				Saml2MessageBinding.POST, false);
		Saml2AuthenticationToken token = token(response, verifying(registration()), mockAuthenticationRequest);
		this.provider.authenticate(token);
	}

	@Test
	public void evaluateInResponseToFailsWhenInResponseToInAssertionOnlyAndCorruptedStoredRequest() {
		Response response = response();
		response.getAssertions().add(signed(assertion()));
		response.getAssertions().add(signed(assertion("SAML2")));
		AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mockedStoredAuthenticationRequest("SAML2",
				Saml2MessageBinding.POST, true);
		Saml2AuthenticationToken token = token(response, verifying(registration()), mockAuthenticationRequest);
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token)).withStackTraceContaining("malformed_request_data");
	}

	@Test
	public void evaluateInResponseToFailsWhenInResponseToInAssertionMismatchWithRequestID() {
		Response response = response();
		response.setInResponseTo("SAML2");
		response.getAssertions().add(signed(assertion("SAML2")));
		response.getAssertions().add(signed(assertion("BAD")));
		AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mockedStoredAuthenticationRequest("SAML2",
				Saml2MessageBinding.POST, false);
		Saml2AuthenticationToken token = token(response, verifying(registration()), mockAuthenticationRequest);
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token)).withStackTraceContaining("invalid_assertion");
	}

	@Test
	public void evaluateInResponseToFailsWhenInResponseToInAssertionOnlyAndMismatchWithRequestID() {
		Response response = response();
		response.getAssertions().add(signed(assertion()));
		response.getAssertions().add(signed(assertion("BAD")));
		AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mockedStoredAuthenticationRequest("SAML2",
				Saml2MessageBinding.POST, false);
		Saml2AuthenticationToken token = token(response, verifying(registration()), mockAuthenticationRequest);
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token)).withStackTraceContaining("invalid_assertion");
	}

	@Test
	public void evaluateInResponseToFailsWhenInResponseInToResponseMismatchWithRequestID() {
		Response response = response();
		response.setInResponseTo("BAD");
		response.getAssertions().add(signed(assertion("SAML2")));
		response.getAssertions().add(signed(assertion("SAML2")));
		AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mockedStoredAuthenticationRequest("SAML2",
				Saml2MessageBinding.POST, false);
		Saml2AuthenticationToken token = token(response, verifying(registration()), mockAuthenticationRequest);
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token)).withStackTraceContaining("invalid_in_response_to");
	}

	@Test
	public void evaluateInResponseToFailsWhenInResponseInToResponseAndCorruptedStoredRequest() {
		Response response = response();
		response.setInResponseTo("SAML2");
		response.getAssertions().add(signed(assertion()));
		response.getAssertions().add(signed(assertion()));
		AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mockedStoredAuthenticationRequest("SAML2",
				Saml2MessageBinding.POST, true);
		Saml2AuthenticationToken token = token(response, verifying(registration()), mockAuthenticationRequest);
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token)).withStackTraceContaining("malformed_request_data");
	}

	@Test
	public void evaluateInResponseToFailsWhenInResponseToInResponseButNoSavedRequest() {
		Response response = response();
		response.setInResponseTo("BAD");
		Saml2AuthenticationToken token = token(response, verifying(registration()));
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token)).withStackTraceContaining("invalid_in_response_to");
	}

	@Test
	public void evaluateInResponseToSucceedsWhenNoInResponseToInResponseOrAssertions() {
		Response response = response();
		response.getAssertions().add(signed(assertion()));
		AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mockedStoredAuthenticationRequest("SAML2",
				Saml2MessageBinding.POST, false);
		Saml2AuthenticationToken token = token(response, verifying(registration()), mockAuthenticationRequest);
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenAssertionContainsAttributesThenItSucceeds() {
		Response response = response();
		Assertion assertion = assertion();
		List<AttributeStatement> attributes = attributeStatements();
		assertion.getAttributeStatements().addAll(attributes);
		response.getAssertions().add(signed(assertion));
		Saml2AuthenticationToken token = token(response, verifying(registration()));
		Authentication authentication = this.provider.authenticate(token);
		Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
		Map<String, Object> expected = new LinkedHashMap<>();
		expected.put("email", Arrays.asList("john.doe@example.com", "doe.john@example.com"));
		expected.put("name", Collections.singletonList("John Doe"));
		expected.put("age", Collections.singletonList(21));
		expected.put("website", Collections.singletonList("https://johndoe.com/"));
		expected.put("registered", Collections.singletonList(true));
		Instant registeredDate = Instant.parse("1970-01-01T00:00:00Z");
		expected.put("registeredDate", Collections.singletonList(registeredDate));
		expected.put("role", Arrays.asList("RoleOne", "RoleTwo")); // gh-11042
		assertThat((String) principal.getFirstAttribute("name")).isEqualTo("John Doe");
		assertThat(principal.getAttributes()).isEqualTo(expected);
		assertThat(principal.getSessionIndexes()).contains("session-index");
	}

	@Test
	public void authenticateWhenAssertionContainsCustomAttributesThenItSucceeds() {
		Response response = response();
		Assertion assertion = assertion();
		AttributeStatement attribute = TestOpenSamlObjects.customAttributeStatement("Address",
				TestCustomOpenSamlObjects.instance());
		assertion.getAttributeStatements().add(attribute);
		response.getAssertions().add(signed(assertion));
		Saml2AuthenticationToken token = token(response, verifying(registration()));
		Authentication authentication = this.provider.authenticate(token);
		Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
		CustomOpenSamlObject address = (CustomOpenSamlObject) principal.getAttribute("Address").get(0);
		assertThat(address.getStreet()).isEqualTo("Test Street");
		assertThat(address.getStreetNumber()).isEqualTo("1");
		assertThat(address.getZIP()).isEqualTo("11111");
		assertThat(address.getCity()).isEqualTo("Test City");
	}

	@Test
	public void authenticateWhenEncryptedAssertionWithoutSignatureThenItFails() {
		Response response = response();
		EncryptedAssertion encryptedAssertion = TestOpenSamlObjects.encrypted(assertion(),
				TestSaml2X509Credentials.assertingPartyEncryptingCredential());
		response.getEncryptedAssertions().add(encryptedAssertion);
		Saml2AuthenticationToken token = token(response, decrypting(verifying(registration())));
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.satisfies(errorOf(Saml2ErrorCodes.INVALID_SIGNATURE, "Did not decrypt response"));
	}

	@Test
	public void authenticateWhenEncryptedAssertionWithSignatureThenItSucceeds() {
		Response response = response();
		Assertion assertion = TestOpenSamlObjects.signed(assertion(),
				TestSaml2X509Credentials.assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID);
		EncryptedAssertion encryptedAssertion = TestOpenSamlObjects.encrypted(assertion,
				TestSaml2X509Credentials.assertingPartyEncryptingCredential());
		response.getEncryptedAssertions().add(encryptedAssertion);
		Saml2AuthenticationToken token = token(signed(response), decrypting(verifying(registration())));
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenEncryptedAssertionWithResponseSignatureThenItSucceeds() {
		Response response = response();
		EncryptedAssertion encryptedAssertion = TestOpenSamlObjects.encrypted(assertion(),
				TestSaml2X509Credentials.assertingPartyEncryptingCredential());
		response.getEncryptedAssertions().add(encryptedAssertion);
		Saml2AuthenticationToken token = token(signed(response), decrypting(verifying(registration())));
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenEncryptedNameIdWithSignatureThenItSucceeds() {
		Response response = response();
		Assertion assertion = assertion();
		NameID nameId = assertion.getSubject().getNameID();
		EncryptedID encryptedID = TestOpenSamlObjects.encrypted(nameId,
				TestSaml2X509Credentials.assertingPartyEncryptingCredential());
		assertion.getSubject().setNameID(null);
		assertion.getSubject().setEncryptedID(encryptedID);
		response.getAssertions().add(signed(assertion));
		Saml2AuthenticationToken token = token(response, decrypting(verifying(registration())));
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenEncryptedAttributeThenDecrypts() {
		Response response = response();
		Assertion assertion = assertion();
		EncryptedAttribute attribute = TestOpenSamlObjects.encrypted("name", "value",
				TestSaml2X509Credentials.assertingPartyEncryptingCredential());
		AttributeStatement statement = build(AttributeStatement.DEFAULT_ELEMENT_NAME);
		statement.getEncryptedAttributes().add(attribute);
		assertion.getAttributeStatements().add(statement);
		response.getAssertions().add(assertion);
		Saml2AuthenticationToken token = token(signed(response), decrypting(verifying(registration())));
		Saml2Authentication authentication = (Saml2Authentication) this.provider.authenticate(token);
		Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
		assertThat(principal.getAttribute("name")).containsExactly("value");
	}

	@Test
	public void authenticateWhenDecryptionKeysAreMissingThenThrowAuthenticationException() {
		Response response = response();
		EncryptedAssertion encryptedAssertion = TestOpenSamlObjects.encrypted(assertion(),
				TestSaml2X509Credentials.assertingPartyEncryptingCredential());
		response.getEncryptedAssertions().add(encryptedAssertion);
		Saml2AuthenticationToken token = token(signed(response), verifying(registration()));
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.satisfies(errorOf(Saml2ErrorCodes.DECRYPTION_ERROR, "Failed to decrypt EncryptedData"));
	}

	@Test
	public void authenticateWhenDecryptionKeysAreWrongThenThrowAuthenticationException() {
		Response response = response();
		EncryptedAssertion encryptedAssertion = TestOpenSamlObjects.encrypted(assertion(),
				TestSaml2X509Credentials.assertingPartyEncryptingCredential());
		response.getEncryptedAssertions().add(encryptedAssertion);
		Saml2AuthenticationToken token = token(signed(response), registration()
				.decryptionX509Credentials((c) -> c.add(TestSaml2X509Credentials.assertingPartyPrivateCredential())));
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.satisfies(errorOf(Saml2ErrorCodes.DECRYPTION_ERROR, "Failed to decrypt EncryptedData"));
	}

	@Test
	public void authenticateWhenAuthenticationHasDetailsThenSucceeds() {
		Response response = response();
		Assertion assertion = assertion();
		assertion.getSubject().getSubjectConfirmations()
				.forEach((sc) -> sc.getSubjectConfirmationData().setAddress("10.10.10.10"));
		response.getAssertions().add(signed(assertion));
		Saml2AuthenticationToken token = token(response, verifying(registration()));
		token.setDetails("some-details");
		Authentication authentication = this.provider.authenticate(token);
		assertThat(authentication.getDetails()).isEqualTo("some-details");
	}

	@Test
	public void writeObjectWhenTypeIsSaml2AuthenticationThenNoException() throws IOException {
		Response response = response();
		Assertion assertion = TestOpenSamlObjects.signed(assertion(),
				TestSaml2X509Credentials.assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID);
		EncryptedAssertion encryptedAssertion = TestOpenSamlObjects.encrypted(assertion,
				TestSaml2X509Credentials.assertingPartyEncryptingCredential());
		response.getEncryptedAssertions().add(encryptedAssertion);
		Saml2AuthenticationToken token = token(signed(response), decrypting(verifying(registration())));
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
		OpenSaml4AuthenticationProvider.AssertionToken assertionToken = new OpenSaml4AuthenticationProvider.AssertionToken(
				assertion, token());
		assertThat(
				OpenSaml4AuthenticationProvider.createDefaultAssertionValidator().convert(assertionToken).hasErrors())
						.isFalse();
	}

	@Test
	public void authenticateWhenDelegatingToDefaultAssertionValidatorThenUses() {
		OpenSaml4AuthenticationProvider provider = new OpenSaml4AuthenticationProvider();
		// @formatter:off
		provider.setAssertionValidator((assertionToken) -> OpenSaml4AuthenticationProvider
				.createDefaultAssertionValidator((token) -> new ValidationContext())
				.convert(assertionToken)
				.concat(new Saml2Error("wrong error", "wrong error"))
		);
		// @formatter:on
		Response response = response();
		Assertion assertion = assertion();
		OneTimeUse oneTimeUse = build(OneTimeUse.DEFAULT_ELEMENT_NAME);
		assertion.getConditions().getConditions().add(oneTimeUse);
		response.getAssertions().add(assertion);
		Saml2AuthenticationToken token = token(signed(response), verifying(registration()));
		// @formatter:off
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> provider.authenticate(token)).isInstanceOf(Saml2AuthenticationException.class)
				.satisfies((error) -> assertThat(error.getSaml2Error().getErrorCode()).isEqualTo(Saml2ErrorCodes.INVALID_ASSERTION));
		// @formatter:on
	}

	// gh-11675
	@Test
	public void authenticateWhenUsingCustomAssertionValidatorThenUses() {
		OpenSaml4AuthenticationProvider provider = new OpenSaml4AuthenticationProvider();
		Consumer<Map<String, Object>> validationParameters = mock(Consumer.class);
		// @formatter:off
		provider.setAssertionValidator(OpenSaml4AuthenticationProvider
				.createDefaultAssertionValidatorWithParameters(validationParameters));
		// @formatter:on
		Response response = response();
		Assertion assertion = assertion();
		OneTimeUse oneTimeUse = build(OneTimeUse.DEFAULT_ELEMENT_NAME);
		assertion.getConditions().getConditions().add(oneTimeUse);
		response.getAssertions().add(assertion);
		Saml2AuthenticationToken token = token(signed(response), verifying(registration()));
		provider.authenticate(token);
		verify(validationParameters).accept(any());
	}

	@Test
	public void authenticateWhenCustomAssertionValidatorThenUses() {
		Converter<OpenSaml4AuthenticationProvider.AssertionToken, Saml2ResponseValidatorResult> validator = mock(
				Converter.class);
		OpenSaml4AuthenticationProvider provider = new OpenSaml4AuthenticationProvider();
		// @formatter:off
		provider.setAssertionValidator((assertionToken) -> OpenSaml4AuthenticationProvider.createDefaultAssertionValidator()
				.convert(assertionToken)
				.concat(validator.convert(assertionToken))
		);
		// @formatter:on
		Response response = response();
		Assertion assertion = assertion();
		response.getAssertions().add(assertion);
		Saml2AuthenticationToken token = token(signed(response), verifying(registration()));
		given(validator.convert(any(OpenSaml4AuthenticationProvider.AssertionToken.class)))
				.willReturn(Saml2ResponseValidatorResult.success());
		provider.authenticate(token);
		verify(validator).convert(any(OpenSaml4AuthenticationProvider.AssertionToken.class));
	}

	@Test
	public void authenticateWhenDefaultConditionValidatorNotUsedThenSignatureStillChecked() {
		OpenSaml4AuthenticationProvider provider = new OpenSaml4AuthenticationProvider();
		provider.setAssertionValidator((assertionToken) -> Saml2ResponseValidatorResult.success());
		Response response = response();
		Assertion assertion = assertion();
		TestOpenSamlObjects.signed(assertion, TestSaml2X509Credentials.relyingPartyDecryptingCredential(),
				RELYING_PARTY_ENTITY_ID); // broken
		// signature
		response.getAssertions().add(assertion);
		Saml2AuthenticationToken token = token(signed(response), verifying(registration()));
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
		OpenSaml4AuthenticationProvider provider = new OpenSaml4AuthenticationProvider();
		provider.setAssertionValidator(
				OpenSaml4AuthenticationProvider.createDefaultAssertionValidator((assertionToken) -> context));
		Response response = response();
		Assertion assertion = assertion();
		response.getAssertions().add(signed(assertion));
		Saml2AuthenticationToken token = token(response, verifying(registration()));
		// @formatter:off
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> provider.authenticate(token)).isInstanceOf(Saml2AuthenticationException.class)
				.satisfies((error) -> assertThat(error).hasMessageContaining("Invalid assertion"));
		// @formatter:on
		verify(context, atLeastOnce()).getStaticParameters();
	}

	@Test
	public void authenticateWithSHA1SignatureThenItSucceeds() throws Exception {
		Response response = response();
		Assertion assertion = TestOpenSamlObjects.signed(assertion(),
				TestSaml2X509Credentials.assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID,
				SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		response.getAssertions().add(assertion);
		Saml2AuthenticationToken token = token(response, verifying(registration()));
		this.provider.authenticate(token);
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
		Saml2AuthenticationToken token = token(response, verifying(registration()));
		ResponseToken responseToken = new ResponseToken(response, token);
		Saml2Authentication authentication = OpenSaml4AuthenticationProvider
				.createDefaultResponseAuthenticationConverter().convert(responseToken);
		assertThat(authentication.getName()).isEqualTo("test@saml.user");
	}

	@Test
	public void authenticateWhenResponseAuthenticationConverterConfiguredThenUses() {
		Converter<ResponseToken, Saml2Authentication> authenticationConverter = mock(Converter.class);
		OpenSaml4AuthenticationProvider provider = new OpenSaml4AuthenticationProvider();
		provider.setResponseAuthenticationConverter(authenticationConverter);
		Response response = TestOpenSamlObjects.signedResponseWithOneAssertion();
		Saml2AuthenticationToken token = token(response, verifying(registration()));
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

	@Test
	public void setResponseElementsDecrypterWhenNullThenIllegalArgument() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.provider.setResponseElementsDecrypter(null));
	}

	@Test
	public void setAssertionElementsDecrypterWhenNullThenIllegalArgument() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.provider.setAssertionElementsDecrypter(null));
	}

	@Test
	public void authenticateWhenCustomResponseElementsDecrypterThenDecryptsResponse() {
		Response response = response();
		Assertion assertion = assertion();
		response.getEncryptedAssertions().add(new EncryptedAssertionBuilder().buildObject());
		TestOpenSamlObjects.signed(response, TestSaml2X509Credentials.assertingPartySigningCredential(),
				RELYING_PARTY_ENTITY_ID);
		Saml2AuthenticationToken token = token(response, verifying(registration()));
		this.provider
				.setResponseElementsDecrypter((tuple) -> tuple.getResponse().getAssertions().add(signed(assertion)));
		Authentication authentication = this.provider.authenticate(token);
		assertThat(authentication.getName()).isEqualTo("test@saml.user");
	}

	@Test
	public void authenticateWhenCustomAssertionElementsDecrypterThenDecryptsAssertion() {
		Response response = response();
		Assertion assertion = assertion();
		EncryptedID id = new EncryptedIDBuilder().buildObject();
		id.setEncryptedData(new EncryptedDataBuilder().buildObject());
		assertion.getSubject().setEncryptedID(id);
		response.getAssertions().add(signed(assertion));
		Saml2AuthenticationToken token = token(response, verifying(registration()));
		this.provider.setAssertionElementsDecrypter((tuple) -> {
			NameID name = new NameIDBuilder().buildObject();
			name.setValue("decrypted name");
			tuple.getAssertion().getSubject().setNameID(name);
		});
		Authentication authentication = this.provider.authenticate(token);
		assertThat(authentication.getName()).isEqualTo("decrypted name");
	}

	@Test
	public void authenticateWhenResponseStatusIsNotSuccessThenFails() {
		Response response = TestOpenSamlObjects.signedResponseWithOneAssertion(
				(r) -> r.setStatus(TestOpenSamlObjects.status(StatusCode.AUTHN_FAILED)));
		Saml2AuthenticationToken token = token(response, verifying(registration()));
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.satisfies(errorOf(Saml2ErrorCodes.INVALID_RESPONSE, "Invalid status"));
	}

	@Test
	public void authenticateWhenResponseStatusIsSuccessThenSucceeds() {
		Response response = TestOpenSamlObjects
				.signedResponseWithOneAssertion((r) -> r.setStatus(TestOpenSamlObjects.successStatus()));
		Saml2AuthenticationToken token = token(response, verifying(registration()));
		Authentication authentication = this.provider.authenticate(token);
		assertThat(authentication.getName()).isEqualTo("test@saml.user");
	}

	@Test
	public void setResponseValidatorWhenNullThenIllegalArgument() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.provider.setResponseValidator(null));
	}

	@Test
	public void authenticateWhenCustomResponseValidatorThenUses() {
		Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2ResponseValidatorResult> validator = mock(
				Converter.class);
		OpenSaml4AuthenticationProvider provider = new OpenSaml4AuthenticationProvider();
		// @formatter:off
		provider.setResponseValidator((responseToken) -> OpenSaml4AuthenticationProvider.createDefaultResponseValidator()
				.convert(responseToken)
				.concat(validator.convert(responseToken))
		);
		// @formatter:on
		Response response = response();
		Assertion assertion = assertion();
		response.getAssertions().add(assertion);
		Saml2AuthenticationToken token = token(signed(response), verifying(registration()));
		given(validator.convert(any(OpenSaml4AuthenticationProvider.ResponseToken.class)))
				.willReturn(Saml2ResponseValidatorResult.success());
		provider.authenticate(token);
		verify(validator).convert(any(OpenSaml4AuthenticationProvider.ResponseToken.class));
	}

	@Test
	public void authenticateWhenAssertionIssuerNotValidThenFailsWithInvalidIssuer() {
		OpenSaml4AuthenticationProvider provider = new OpenSaml4AuthenticationProvider();
		Response response = response();
		Assertion assertion = assertion();
		assertion.setIssuer(TestOpenSamlObjects.issuer("https://invalid.idp.test/saml2/idp"));
		response.getAssertions().add(assertion);
		Saml2AuthenticationToken token = token(signed(response), verifying(registration()));
		assertThatExceptionOfType(Saml2AuthenticationException.class).isThrownBy(() -> provider.authenticate(token))
				.withMessageContaining("did not match any valid issuers");
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

	private Consumer<Saml2AuthenticationException> errorOf(String errorCode) {
		return errorOf(errorCode, null);
	}

	private Consumer<Saml2AuthenticationException> errorOf(String errorCode, String description) {
		return (ex) -> {
			assertThat(ex.getSaml2Error().getErrorCode()).isEqualTo(errorCode);
			if (StringUtils.hasText(description)) {
				assertThat(ex.getSaml2Error().getDescription()).contains(description);
			}
		};
	}

	private Response response() {
		Response response = TestOpenSamlObjects.response();
		response.setIssueInstant(Instant.now());
		return response;
	}

	private Response response(String destination, String issuerEntityId) {
		Response response = TestOpenSamlObjects.response(destination, issuerEntityId);
		response.setIssueInstant(Instant.now());
		return response;
	}

	private AuthnRequest request() {
		AuthnRequest request = TestOpenSamlObjects.authnRequest();
		return request;
	}

	private String serializedRequest(AuthnRequest request, Saml2MessageBinding binding) {
		String xml = serialize(request);
		return (binding == Saml2MessageBinding.POST) ? Saml2Utils.samlEncode(xml.getBytes(StandardCharsets.UTF_8))
				: Saml2Utils.samlEncode(Saml2Utils.samlDeflate(xml));
	}

	private Assertion assertion(String inResponseTo) {
		Assertion assertion = TestOpenSamlObjects.assertion();
		assertion.setIssueInstant(Instant.now());
		for (SubjectConfirmation confirmation : assertion.getSubject().getSubjectConfirmations()) {
			SubjectConfirmationData data = confirmation.getSubjectConfirmationData();
			data.setNotBefore(Instant.now().minus(Duration.ofMillis(5 * 60 * 1000)));
			data.setNotOnOrAfter(Instant.now().plus(Duration.ofMillis(5 * 60 * 1000)));
			if (StringUtils.hasText(inResponseTo)) {
				data.setInResponseTo(inResponseTo);
			}
		}
		Conditions conditions = assertion.getConditions();
		conditions.setNotBefore(Instant.now().minus(Duration.ofMillis(5 * 60 * 1000)));
		conditions.setNotOnOrAfter(Instant.now().plus(Duration.ofMillis(5 * 60 * 1000)));
		return assertion;
	}

	private Assertion assertion() {
		return assertion(null);
	}

	private <T extends SignableSAMLObject> T signed(T toSign) {
		TestOpenSamlObjects.signed(toSign, TestSaml2X509Credentials.assertingPartySigningCredential(),
				RELYING_PARTY_ENTITY_ID);
		return toSign;
	}

	private List<AttributeStatement> attributeStatements() {
		List<AttributeStatement> attributeStatements = TestOpenSamlObjects.attributeStatements();
		AttributeBuilder attributeBuilder = new AttributeBuilder();
		Attribute registeredDateAttr = attributeBuilder.buildObject();
		registeredDateAttr.setName("registeredDate");
		XSDateTime registeredDate = new XSDateTimeBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
				XSDateTime.TYPE_NAME);
		registeredDate.setValue(Instant.parse("1970-01-01T00:00:00Z"));
		registeredDateAttr.getAttributeValues().add(registeredDate);
		attributeStatements.iterator().next().getAttributes().add(registeredDateAttr);
		return attributeStatements;
	}

	private Saml2AuthenticationToken token() {
		Response response = response();
		RelyingPartyRegistration registration = verifying(registration()).build();
		return new Saml2AuthenticationToken(registration, serialize(response));
	}

	private Saml2AuthenticationToken token(Response response, RelyingPartyRegistration.Builder registration) {
		return new Saml2AuthenticationToken(registration.build(), serialize(response));
	}

	private Saml2AuthenticationToken token(Response response, RelyingPartyRegistration.Builder registration,
			AbstractSaml2AuthenticationRequest authenticationRequest) {
		return new Saml2AuthenticationToken(registration.build(), serialize(response), authenticationRequest);
	}

	private AbstractSaml2AuthenticationRequest mockedStoredAuthenticationRequest(String requestId,
			Saml2MessageBinding binding, boolean corruptRequestString) {
		AuthnRequest request = request();
		if (requestId != null) {
			request.setID(requestId);
		}
		String serializedRequest = serializedRequest(request, binding);
		if (corruptRequestString) {
			serializedRequest = serializedRequest.substring(2, serializedRequest.length() - 2);
		}
		AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mock(AbstractSaml2AuthenticationRequest.class);
		given(mockAuthenticationRequest.getSamlRequest()).willReturn(serializedRequest);
		given(mockAuthenticationRequest.getBinding()).willReturn(binding);
		return mockAuthenticationRequest;
	}

	private RelyingPartyRegistration.Builder registration() {
		return TestRelyingPartyRegistrations.noCredentials().entityId(RELYING_PARTY_ENTITY_ID)
				.assertionConsumerServiceLocation(DESTINATION)
				.assertingPartyDetails((party) -> party.entityId(ASSERTING_PARTY_ENTITY_ID));
	}

	private RelyingPartyRegistration.Builder verifying(RelyingPartyRegistration.Builder builder) {
		return builder.assertingPartyDetails((party) -> party
				.verificationX509Credentials((c) -> c.add(TestSaml2X509Credentials.relyingPartyVerifyingCredential())));
	}

	private RelyingPartyRegistration.Builder decrypting(RelyingPartyRegistration.Builder builder) {
		return builder
				.decryptionX509Credentials((c) -> c.add(TestSaml2X509Credentials.relyingPartyDecryptingCredential()));
	}

}
