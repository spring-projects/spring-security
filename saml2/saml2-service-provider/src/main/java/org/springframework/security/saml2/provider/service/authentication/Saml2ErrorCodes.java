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

/**
 * A list of SAML known 2 error codes used during SAML authentication.
 *
 * @since 5.2
 * @deprecated Use {@link org.springframework.security.saml2.core.Saml2ErrorCodes} instead
 */
@Deprecated
public interface Saml2ErrorCodes {
	/**
	 * SAML Data does not represent a SAML 2 Response object.
	 * A valid XML object was received, but that object was not a
	 * SAML 2 Response object of type {@code ResponseType} per specification
	 * https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf#page=46
	 */
	String UNKNOWN_RESPONSE_CLASS = org.springframework.security.saml2.core.Saml2ErrorCodes.UNKNOWN_RESPONSE_CLASS;
	/**
	 * The response data is malformed or incomplete.
	 * An invalid XML object was received, and XML unmarshalling failed.
	 */
	String MALFORMED_RESPONSE_DATA = org.springframework.security.saml2.core.Saml2ErrorCodes.MALFORMED_RESPONSE_DATA;
	/**
	 * Response destination does not match the request URL.
	 * A SAML 2 response object was received at a URL that
	 * did not match the URL stored in the {code Destination} attribute
	 * in the Response object.
	 * https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf#page=38
	 */
	String INVALID_DESTINATION = org.springframework.security.saml2.core.Saml2ErrorCodes.INVALID_DESTINATION;
	/**
	 * The assertion was not valid.
	 * The assertion used for authentication failed validation.
	 * Details around the failure will be present in the error description.
	 */
	String INVALID_ASSERTION = org.springframework.security.saml2.core.Saml2ErrorCodes.INVALID_ASSERTION;
	/**
	 * The signature of response or assertion was invalid.
	 * Either the response or the assertion was missing a signature
	 * or the signature could not be verified using the system's
	 * configured credentials. Most commonly the IDP's
	 * X509 certificate.
	 */
	String INVALID_SIGNATURE = org.springframework.security.saml2.core.Saml2ErrorCodes.INVALID_SIGNATURE;
	/**
	 * The assertion did not contain a subject element.
	 * The subject element, type SubjectType, contains
	 * a {@code NameID} or an {@code EncryptedID} that is used
	 * to assign the authenticated principal an identifier,
	 * typically a username.
	 *
	 * https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf#page=18
	 */
	String SUBJECT_NOT_FOUND = org.springframework.security.saml2.core.Saml2ErrorCodes.SUBJECT_NOT_FOUND;
	/**
	 * The subject did not contain a user identifier
	 * The assertion contained a subject element, but the subject
	 * element did not have a {@code NameID} or {@code EncryptedID}
	 * element
	 *
	 * https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf#page=18
	 */
	String USERNAME_NOT_FOUND = org.springframework.security.saml2.core.Saml2ErrorCodes.USERNAME_NOT_FOUND;
	/**
	 * The system failed to decrypt an assertion or a name identifier.
	 * This error code will be thrown if the decryption of either a
	 * {@code EncryptedAssertion} or {@code EncryptedID} fails.
	 * https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf#page=17
	 */
	String DECRYPTION_ERROR = org.springframework.security.saml2.core.Saml2ErrorCodes.DECRYPTION_ERROR;
	/**
	 * An Issuer element contained a value that didn't
	 * https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf#page=15
	 */
	String INVALID_ISSUER = org.springframework.security.saml2.core.Saml2ErrorCodes.INVALID_ISSUER;
	/**
	 * An error happened during validation.
	 * Used when internal, non classified, errors are caught during the
	 * authentication process.
	 */
	String INTERNAL_VALIDATION_ERROR = org.springframework.security.saml2.core.Saml2ErrorCodes.INTERNAL_VALIDATION_ERROR;
	/**
	 * The relying party registration was not found.
	 * The registration ID did not correspond to any relying party registration.
	 */
	String RELYING_PARTY_REGISTRATION_NOT_FOUND = org.springframework.security.saml2.core.Saml2ErrorCodes.RELYING_PARTY_REGISTRATION_NOT_FOUND;
}
