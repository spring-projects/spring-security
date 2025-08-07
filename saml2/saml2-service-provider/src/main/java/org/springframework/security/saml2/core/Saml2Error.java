/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.saml2.core;

import java.io.Serializable;

import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

/**
 * A representation of an SAML 2.0 Error.
 *
 * <p>
 * At a minimum, an error response will contain an error code. The commonly used error
 * code are defined in this class or a new codes can be defined in the future as arbitrary
 * strings.
 * </p>
 *
 * @since 5.2
 */
public class Saml2Error implements Serializable {

	private static final long serialVersionUID = 620L;

	private final String errorCode;

	private final String description;

	/**
	 * Constructs a {@code Saml2Error} using the provided parameters.
	 * @param errorCode the error code
	 * @param description the error description
	 */
	public Saml2Error(String errorCode, String description) {
		Assert.hasText(errorCode, "errorCode cannot be empty");
		this.errorCode = errorCode;
		this.description = description;
	}

	/**
	 * Construct an {@link Saml2ErrorCodes#INVALID_RESPONSE} error
	 * @param description the error description
	 * @return the resulting {@link Saml2Error}
	 * @since 7.0
	 */
	public static Saml2Error invalidResponse(String description) {
		return new Saml2Error(Saml2ErrorCodes.INVALID_RESPONSE, description);
	}

	/**
	 * Construct an {@link Saml2ErrorCodes#INTERNAL_VALIDATION_ERROR} error
	 * @param description the error description
	 * @return the resulting {@link Saml2Error}
	 * @since 7.0
	 */
	public static Saml2Error internalValidationError(String description) {
		return new Saml2Error(Saml2ErrorCodes.INTERNAL_VALIDATION_ERROR, description);
	}

	/**
	 * Construct an {@link Saml2ErrorCodes#MALFORMED_RESPONSE_DATA} error
	 * @param description the error description
	 * @return the resulting {@link Saml2Error}
	 * @since 7.0
	 */
	public static Saml2Error malformedResponseData(String description) {
		return new Saml2Error(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA, description);
	}

	/**
	 * Construct an {@link Saml2ErrorCodes#DECRYPTION_ERROR} error
	 * @param description the error description
	 * @return the resulting {@link Saml2Error}
	 * @since 7.0
	 */
	public static Saml2Error decryptionError(String description) {
		return new Saml2Error(Saml2ErrorCodes.DECRYPTION_ERROR, description);
	}

	/**
	 * Construct an {@link Saml2ErrorCodes#RELYING_PARTY_REGISTRATION_NOT_FOUND} error
	 * @param description the error description
	 * @return the resulting {@link Saml2Error}
	 * @since 7.0
	 */
	public static Saml2Error relyingPartyRegistrationNotFound(String description) {
		return new Saml2Error(Saml2ErrorCodes.RELYING_PARTY_REGISTRATION_NOT_FOUND, description);
	}

	/**
	 * Construct an {@link Saml2ErrorCodes#SUBJECT_NOT_FOUND} error
	 * @param description the error description
	 * @return the resulting {@link Saml2Error}
	 * @since 7.0
	 */
	public static Saml2Error subjectNotFound(String description) {
		return new Saml2Error(Saml2ErrorCodes.SUBJECT_NOT_FOUND, description);
	}

	/**
	 * Returns the error code.
	 * @return the error code
	 */
	public final String getErrorCode() {
		return this.errorCode;
	}

	/**
	 * Returns the error description.
	 * @return the error description
	 */
	public final String getDescription() {
		return this.description;
	}

	@Override
	public String toString() {
		return "[" + this.getErrorCode() + "] " + ((this.getDescription() != null) ? this.getDescription() : "");
	}

}
