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

package org.springframework.security.webauthn.util;

import com.webauthn4j.util.exception.WebAuthnException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.webauthn.exception.*;

/**
 * Internal utility to handle exceptions
 *
 * @author Yoshikazu Nojima
 */
public class ExceptionUtil {

	private ExceptionUtil() {
	}

	/**
	 * Wraps WebAuthnAuthentication to proper {@link RuntimeException} (mainly {@link AuthenticationException} subclass.
	 *
	 * @param e exception to be wrapped
	 * @return wrapping exception
	 */
	@SuppressWarnings("squid:S3776")
	public static RuntimeException wrapWithAuthenticationException(WebAuthnException e) {
		// ValidationExceptions
		if (e instanceof com.webauthn4j.validator.exception.BadAaguidException) {
			return new BadAaguidException(e.getMessage(), e);
		} else if (e instanceof com.webauthn4j.validator.exception.BadAlgorithmException) {
			return new BadAlgorithmException(e.getMessage(), e);
		} else if (e instanceof com.webauthn4j.validator.exception.BadAttestationStatementException) {
			if (e instanceof com.webauthn4j.validator.exception.KeyDescriptionValidationException) {
				return new KeyDescriptionValidationException(e.getMessage(), e);
			} else {
				return new BadAttestationStatementException(e.getMessage(), e);
			}
		} else if (e instanceof com.webauthn4j.validator.exception.BadChallengeException) {
			return new BadChallengeException(e.getMessage(), e);
		} else if (e instanceof com.webauthn4j.validator.exception.BadOriginException) {
			return new BadOriginException(e.getMessage(), e);
		} else if (e instanceof com.webauthn4j.validator.exception.BadRpIdException) {
			return new BadRpIdException(e.getMessage(), e);
		} else if (e instanceof com.webauthn4j.validator.exception.BadSignatureException) {
			return new BadSignatureException(e.getMessage(), e);
		} else if (e instanceof com.webauthn4j.validator.exception.CertificateException) {
			return new CertificateException(e.getMessage(), e);
		} else if (e instanceof com.webauthn4j.validator.exception.ConstraintViolationException) {
			return new ConstraintViolationException(e.getMessage(), e);
		} else if (e instanceof com.webauthn4j.validator.exception.MaliciousCounterValueException) {
			return new MaliciousCounterValueException(e.getMessage(), e);
		} else if (e instanceof com.webauthn4j.validator.exception.MaliciousDataException) {
			return new MaliciousDataException(e.getMessage(), e);
		} else if (e instanceof com.webauthn4j.validator.exception.MissingChallengeException) {
			return new MissingChallengeException(e.getMessage(), e);
		} else if (e instanceof com.webauthn4j.validator.exception.PublicKeyMismatchException) {
			return new PublicKeyMismatchException(e.getMessage(), e);
		} else if (e instanceof com.webauthn4j.validator.exception.SelfAttestationProhibitedException) {
			return new SelfAttestationProhibitedException(e.getMessage(), e);
		} else if (e instanceof com.webauthn4j.validator.exception.TokenBindingException) {
			return new TokenBindingException(e.getMessage(), e);
		} else if (e instanceof com.webauthn4j.validator.exception.TrustAnchorNotFoundException) {
			return new TrustAnchorNotFoundException(e.getMessage(), e);
		} else if (e instanceof com.webauthn4j.validator.exception.UnexpectedExtensionException) {
			return new UnexpectedExtensionException(e.getMessage(), e);
		} else if (e instanceof com.webauthn4j.validator.exception.UserNotPresentException) {
			return new UserNotPresentException(e.getMessage(), e);
		} else if (e instanceof com.webauthn4j.validator.exception.UserNotVerifiedException) {
			return new UserNotVerifiedException(e.getMessage(), e);
		} else if (e instanceof com.webauthn4j.validator.exception.ValidationException) {
			return new ValidationException("WebAuthn validation error", e);
		}
		// DataConversionException
		else if (e instanceof com.webauthn4j.converter.exception.DataConversionException) {
			return new DataConversionException("WebAuthn data conversion error", e);
		} else {
			return new AuthenticationServiceException(null, e);
		}
	}
}
