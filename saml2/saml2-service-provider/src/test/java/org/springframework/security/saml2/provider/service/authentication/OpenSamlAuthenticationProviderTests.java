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

import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.Saml2Exception;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.opensaml.saml.common.assertion.AssertionValidationException;
import org.opensaml.saml.common.assertion.ValidationContext;
import org.opensaml.saml.common.assertion.ValidationResult;
import org.opensaml.saml.saml2.assertion.SAML20AssertionValidator;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.EncryptedID;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Subject;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.util.Collections;

import static java.util.Collections.emptyList;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.springframework.test.util.AssertionErrors.assertTrue;
import static org.springframework.util.StringUtils.hasText;

@RunWith(PowerMockRunner.class)
@PrepareForTest({OpenSamlImplementation.class, OpenSamlAuthenticationProvider.class})
public class OpenSamlAuthenticationProviderTests {

	private OpenSamlAuthenticationProvider provider;
	private OpenSamlImplementation saml;

	@Rule
	ExpectedException exception = ExpectedException.none();
	private Saml2AuthenticationToken token;

	@Before
	public void setup() {
		saml = PowerMockito.mock(OpenSamlImplementation.class);
		PowerMockito.mockStatic(OpenSamlImplementation.class);
		when(OpenSamlImplementation.getInstance()).thenReturn(saml);

		provider = new OpenSamlAuthenticationProvider();
		token = new Saml2AuthenticationToken(
				"responseXml",
				"recipientUri",
				"idpEntityId",
				"localSpEntityId",
				emptyList()
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
		when(saml.resolve(any(String.class))).thenReturn(mock(Assertion.class));
		exception.expect(authenticationMatcher(Saml2ErrorCodes.UNKNOWN_RESPONSE_CLASS));
		provider.authenticate(token);
	}

	@Test
	public void authenticateWhenXmlErrorThenThrowAuthenticationException() {
		when(saml.resolve(any(String.class))).thenThrow(new Saml2Exception("test"));
		exception.expect(authenticationMatcher(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA));
		provider.authenticate(token);
	}

	@Test
	public void authenticateWhenInvalidDestinationThenThrowAuthenticationException() {
		final Response response = mock(Response.class);
		when(saml.resolve(any(String.class))).thenReturn(response);
		when(response.getDestination()).thenReturn("invalidRecipient");
		exception.expect(authenticationMatcher(Saml2ErrorCodes.INVALID_DESTINATION));
		provider.authenticate(token);
	}

	@Test
	public void authenticateWhenNoAssertionsPresentThenThrowAuthenticationException() {
		final Response response = mock(Response.class);
		final Issuer issuer = mock(Issuer.class);
		when(saml.resolve(any(String.class))).thenReturn(response);
		when(response.getDestination()).thenReturn(token.getRecipientUri());
		when(response.isSigned()).thenReturn(false);
		when(response.getAssertions()).thenReturn(emptyList());
		when(response.getEncryptedAssertions()).thenReturn(emptyList());
		when(response.getIssuer()).thenReturn(issuer);
		when(issuer.getValue()).thenReturn(token.getIdpEntityId());
		exception.expect(
				authenticationMatcher(
						Saml2ErrorCodes.MALFORMED_RESPONSE_DATA,
						"No assertions found in response."
				)
		);
		provider.authenticate(token);
	}

	@Test
	public void authenticateWhenInvalidSignatureThenThrowAuthenticationException() {
		final Response response = mock(Response.class);
		final Issuer issuer = mock(Issuer.class);
		final Assertion assertion = mock(Assertion.class);
		when(saml.resolve(any(String.class))).thenReturn(response);
		when(response.getDestination()).thenReturn(token.getRecipientUri());
		when(response.isSigned()).thenReturn(false);
		when(response.getAssertions()).thenReturn(Collections.singletonList(assertion));
		when(response.getEncryptedAssertions()).thenReturn(emptyList());
		when(response.getIssuer()).thenReturn(issuer);
		when(issuer.getValue()).thenReturn(token.getIdpEntityId());
		when(issuer.getValue()).thenReturn(token.getIdpEntityId());

		exception.expect(
				authenticationMatcher(
						Saml2ErrorCodes.INVALID_SIGNATURE
				)
		);
		provider.authenticate(token);
	}

	@Test
	public void authenticateWhenOpenSAMLValidationErrorThenThrowAuthenticationException() throws Exception {
		final Response response = mock(Response.class);
		final Issuer issuer = mock(Issuer.class);
		final Assertion assertion = mock(Assertion.class);
		final SAML20AssertionValidator validator = mock(SAML20AssertionValidator.class);
		when(saml.resolve(any(String.class))).thenReturn(response);
		when(response.getDestination()).thenReturn(token.getRecipientUri());
		when(response.isSigned()).thenReturn(false);
		when(response.getAssertions()).thenReturn(Collections.singletonList(assertion));
		when(response.getEncryptedAssertions()).thenReturn(emptyList());
		when(response.getIssuer()).thenReturn(issuer);
		when(issuer.getValue()).thenReturn(token.getIdpEntityId());


		OpenSamlAuthenticationProvider spyProvider = PowerMockito.spy(this.provider);
		doReturn(true).when(
				spyProvider,
				"hasValidSignature",
				any(Assertion.class),
				any(Saml2AuthenticationToken.class)
		);
		doReturn(false).when(
				spyProvider,
				"hasValidSignature",
				any(Response.class),
				any(Saml2AuthenticationToken.class)
		);
		doReturn(validator).when(spyProvider, "getAssertionValidator", any(Saml2AuthenticationToken.class));
		when(validator.validate(
				any(Assertion.class),
				any(ValidationContext.class)
		)).thenReturn(ValidationResult.INVALID);
		exception.expect(
				authenticationMatcher(
						Saml2ErrorCodes.INVALID_ASSERTION
				)
		);
		spyProvider.authenticate(token);
	}

	@Test
	public void authenticateWhenInternalErrorThenCatchAndThrowAuthenticationException() throws Exception {
		final Response response = mock(Response.class);
		final Issuer issuer = mock(Issuer.class);
		final Assertion assertion = mock(Assertion.class);
		final SAML20AssertionValidator validator = mock(SAML20AssertionValidator.class);
		when(saml.resolve(any(String.class))).thenReturn(response);
		when(response.getDestination()).thenReturn(token.getRecipientUri());
		when(response.isSigned()).thenReturn(false);
		when(response.getAssertions()).thenReturn(Collections.singletonList(assertion));
		when(response.getEncryptedAssertions()).thenReturn(emptyList());
		when(response.getIssuer()).thenReturn(issuer);
		when(issuer.getValue()).thenReturn(token.getIdpEntityId());


		OpenSamlAuthenticationProvider spyProvider = PowerMockito.spy(this.provider);
		doReturn(true).when(
				spyProvider,
				"hasValidSignature",
				any(Assertion.class),
				any(Saml2AuthenticationToken.class)
		);
		doReturn(false).when(
				spyProvider,
				"hasValidSignature",
				any(Response.class),
				any(Saml2AuthenticationToken.class)
		);
		doReturn(validator).when(spyProvider, "getAssertionValidator", any(Saml2AuthenticationToken.class));
		when(validator.validate(
				any(Assertion.class),
				any(ValidationContext.class)
		)).thenThrow(new AssertionValidationException());
		exception.expect(
				authenticationMatcher(
						Saml2ErrorCodes.INTERNAL_VALIDATION_ERROR
				)
		);
		spyProvider.authenticate(token);
	}

	@Test
	public void authenticateWhenMissingSubjectThenThrowAuthenticationException() throws Exception {
		final Response response = mock(Response.class);
		final Issuer issuer = mock(Issuer.class);
		final Assertion assertion = mock(Assertion.class);
		when(saml.resolve(any(String.class))).thenReturn(response);
		when(response.getDestination()).thenReturn(token.getRecipientUri());
		when(response.isSigned()).thenReturn(false);
		when(response.getAssertions()).thenReturn(Collections.singletonList(assertion));
		when(response.getEncryptedAssertions()).thenReturn(emptyList());
		when(response.getIssuer()).thenReturn(issuer);
		when(issuer.getValue()).thenReturn(token.getIdpEntityId());


		OpenSamlAuthenticationProvider spyProvider = PowerMockito.spy(this.provider);
		doReturn(true).when(
				spyProvider,
				"hasValidSignature",
				any(Assertion.class),
				any(Saml2AuthenticationToken.class)
		);
		doReturn(false).when(
				spyProvider,
				"hasValidSignature",
				any(Response.class),
				any(Saml2AuthenticationToken.class)
		);
		PowerMockito.doNothing()
				.when(
						spyProvider,
						"validateAssertion",
						anyString(),
						any(Assertion.class),
						any(Saml2AuthenticationToken.class),
						anyBoolean()
				);

		exception.expect(
				authenticationMatcher(
						Saml2ErrorCodes.SUBJECT_NOT_FOUND
				)
		);
		spyProvider.authenticate(token);
	}

	@Test
	public void authenticateWhenUsernameMissingThenThrowAuthenticationException() throws Exception {
		final Response response = mock(Response.class);
		final Issuer issuer = mock(Issuer.class);
		final Assertion assertion = mock(Assertion.class);
		final Subject subject = mock(Subject.class);
		when(saml.resolve(any(String.class))).thenReturn(response);
		when(response.getDestination()).thenReturn(token.getRecipientUri());
		when(response.isSigned()).thenReturn(false);
		when(response.getAssertions()).thenReturn(Collections.singletonList(assertion));
		when(response.getEncryptedAssertions()).thenReturn(emptyList());
		when(response.getIssuer()).thenReturn(issuer);
		when(issuer.getValue()).thenReturn(token.getIdpEntityId());
		when(assertion.getSubject()).thenReturn(subject);


		OpenSamlAuthenticationProvider spyProvider = PowerMockito.spy(this.provider);
		doReturn(true).when(
				spyProvider,
				"hasValidSignature",
				any(Assertion.class),
				any(Saml2AuthenticationToken.class)
		);
		doReturn(false).when(
				spyProvider,
				"hasValidSignature",
				any(Response.class),
				any(Saml2AuthenticationToken.class)
		);
		PowerMockito.doNothing()
				.when(
						spyProvider,
						"validateAssertion",
						anyString(),
						any(Assertion.class),
						any(Saml2AuthenticationToken.class),
						anyBoolean()
				);

		exception.expect(
				authenticationMatcher(
						Saml2ErrorCodes.USERNAME_NOT_FOUND
				)
		);
		spyProvider.authenticate(token);
	}

	@Test
	public void authenticateWhenDecryptionKeysAreMissingThenThrowAuthenticationException() throws Exception {
		final Response response = mock(Response.class);
		final Issuer issuer = mock(Issuer.class);
		final Assertion assertion = mock(Assertion.class);
		final Subject subject = mock(Subject.class);
		final EncryptedID nameID = mock(EncryptedID.class);
		when(saml.resolve(any(String.class))).thenReturn(response);
		when(response.getDestination()).thenReturn(token.getRecipientUri());
		when(response.isSigned()).thenReturn(false);
		when(response.getAssertions()).thenReturn(Collections.singletonList(assertion));
		when(response.getEncryptedAssertions()).thenReturn(emptyList());
		when(response.getIssuer()).thenReturn(issuer);
		when(issuer.getValue()).thenReturn(token.getIdpEntityId());
		when(assertion.getSubject()).thenReturn(subject);
		when(subject.getEncryptedID()).thenReturn(nameID);


		OpenSamlAuthenticationProvider spyProvider = PowerMockito.spy(this.provider);
		doReturn(true).when(
				spyProvider,
				"hasValidSignature",
				any(Assertion.class),
				any(Saml2AuthenticationToken.class)
		);
		doReturn(false).when(
				spyProvider,
				"hasValidSignature",
				any(Response.class),
				any(Saml2AuthenticationToken.class)
		);
		PowerMockito.doNothing()
				.when(
						spyProvider,
						"validateAssertion",
						anyString(),
						any(Assertion.class),
						any(Saml2AuthenticationToken.class),
						anyBoolean()
				);

		exception.expect(
				authenticationMatcher(
						Saml2ErrorCodes.DECRYPTION_ERROR,
						"No valid decryption credentials found."
				)
		);
		spyProvider.authenticate(token);
	}

	@Test
	public void authenticateWhenDecryptionKeyIsMissingThenThrowAuthenticationException() throws Exception {
		final Response response = mock(Response.class);
		final Issuer issuer = mock(Issuer.class);
		final EncryptedAssertion assertion = mock(EncryptedAssertion.class);
		when(saml.resolve(any(String.class))).thenReturn(response);
		when(response.getDestination()).thenReturn(token.getRecipientUri());
		when(response.isSigned()).thenReturn(false);
		when(response.getIssuer()).thenReturn(issuer);
		when(issuer.getValue()).thenReturn(token.getIdpEntityId());
		when(response.getEncryptedAssertions()).thenReturn(Collections.singletonList(assertion));

		OpenSamlAuthenticationProvider spyProvider = PowerMockito.spy(this.provider);
		doReturn(false).when(
				spyProvider,
				"hasValidSignature",
				any(Response.class),
				any(Saml2AuthenticationToken.class)
		);

		exception.expect(
				authenticationMatcher(
						Saml2ErrorCodes.DECRYPTION_ERROR,
						"No valid decryption credentials found."
				)
		);
		spyProvider.authenticate(token);
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
			public void describeTo(Description description) {
				description.appendText("Expecting a " + Saml2AuthenticationException.class.getName() +
						" with code:" + code + " and description:" + description
				)
						.appendValue(value);
			}
		};
	}

}
