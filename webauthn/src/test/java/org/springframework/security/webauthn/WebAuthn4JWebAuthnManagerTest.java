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

package org.springframework.security.webauthn;

import com.webauthn4j.util.exception.WebAuthnException;
import com.webauthn4j.validator.WebAuthnAuthenticationContextValidator;
import com.webauthn4j.validator.WebAuthnRegistrationContextValidator;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.webauthn.challenge.WebAuthnChallengeImpl;
import org.springframework.security.webauthn.exception.*;
import org.springframework.security.webauthn.server.WebAuthnOrigin;
import org.springframework.security.webauthn.server.WebAuthnServerProperty;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

public class WebAuthn4JWebAuthnManagerTest {

	private WebAuthnRegistrationContextValidator registrationContextValidator = mock(WebAuthnRegistrationContextValidator.class);
	private WebAuthnAuthenticationContextValidator authenticationContextValidator = mock(WebAuthnAuthenticationContextValidator.class);
	private WebAuthnDataConverter webAuthnDataConverter = new WebAuthnDataConverter();
	private WebAuthnManager target = new WebAuthn4JWebAuthnManager(registrationContextValidator, authenticationContextValidator, webAuthnDataConverter);

	@Test(expected = BadAttestationStatementException.class)
	public void verifyRegistrationData_caught_exception_test() {

		doThrow(new com.webauthn4j.validator.exception.BadAttestationStatementException("dummy"))
				.when(registrationContextValidator).validate(any());

		MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
		mockHttpServletRequest.setScheme("https");
		mockHttpServletRequest.setServerName("example.com");
		mockHttpServletRequest.setServerPort(443);

		byte[] clientDataJSON = new byte[0]; //dummy
		byte[] attestationObject = new byte[0]; //dummy
		WebAuthnServerProperty serverProperty = new WebAuthnServerProperty(
				new WebAuthnOrigin("https://example.com"),
				"example.com",
				new WebAuthnChallengeImpl(),
				new byte[]{0x43, 0x21}
		);

		target.verifyRegistrationData(new WebAuthnRegistrationData(clientDataJSON, attestationObject, null, null, serverProperty, null));

	}

	@Test
	public void wrapWithAuthenticationException_test() {

		Map<WebAuthnException, Class> map = new HashMap<>();
		map.put(new com.webauthn4j.validator.exception.BadAaguidException("dummy"), BadAaguidException.class);
		map.put(new com.webauthn4j.validator.exception.BadAlgorithmException("dummy"), BadAlgorithmException.class);
		map.put(new com.webauthn4j.validator.exception.BadAttestationStatementException("dummy"), BadAttestationStatementException.class);
		map.put(new com.webauthn4j.validator.exception.KeyDescriptionValidationException("dummy"), KeyDescriptionValidationException.class);
		map.put(new com.webauthn4j.validator.exception.BadChallengeException("dummy"), BadChallengeException.class);
		map.put(new com.webauthn4j.validator.exception.BadOriginException("dummy"), BadOriginException.class);
		map.put(new com.webauthn4j.validator.exception.BadRpIdException("dummy"), BadRpIdException.class);
		map.put(new com.webauthn4j.validator.exception.BadSignatureException("dummy"), BadSignatureException.class);
		map.put(new com.webauthn4j.validator.exception.CertificateException("dummy"), CertificateException.class);
		map.put(new com.webauthn4j.validator.exception.ConstraintViolationException("dummy"), ConstraintViolationException.class);
		map.put(new com.webauthn4j.validator.exception.MaliciousCounterValueException("dummy"), MaliciousCounterValueException.class);
		map.put(new com.webauthn4j.validator.exception.MaliciousDataException("dummy"), MaliciousDataException.class);
		map.put(new com.webauthn4j.validator.exception.MissingChallengeException("dummy"), MissingChallengeException.class);
		map.put(new com.webauthn4j.validator.exception.PublicKeyMismatchException("dummy"), PublicKeyMismatchException.class);
		map.put(new com.webauthn4j.validator.exception.SelfAttestationProhibitedException("dummy"), SelfAttestationProhibitedException.class);
		map.put(new com.webauthn4j.validator.exception.TokenBindingException("dummy"), TokenBindingException.class);
		map.put(new com.webauthn4j.validator.exception.TrustAnchorNotFoundException("dummy"), TrustAnchorNotFoundException.class);
		map.put(new com.webauthn4j.validator.exception.UnexpectedExtensionException("dummy"), UnexpectedExtensionException.class);
		map.put(new com.webauthn4j.validator.exception.UserNotPresentException("dummy"), UserNotPresentException.class);
		map.put(new com.webauthn4j.validator.exception.UserNotVerifiedException("dummy"), UserNotVerifiedException.class);
		map.put(new UnknownValidationException("dummy"), ValidationException.class);
		map.put(new com.webauthn4j.converter.exception.DataConversionException("dummy"), DataConversionException.class);
		map.put(new WebAuthnException("dummy"), AuthenticationServiceException.class);

		for (Map.Entry<WebAuthnException, Class> entry : map.entrySet()) {
			assertThat(WebAuthn4JWebAuthnManager.wrapWithAuthenticationException(entry.getKey())).isInstanceOf(entry.getValue());
		}
	}

	static class UnknownValidationException extends com.webauthn4j.validator.exception.ValidationException {

		UnknownValidationException(String message) {
			super(message);
		}
	}

}
