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
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.util.Assert;

/**
 * This exception is thrown for all SAML 2.0 related {@link Authentication} errors.
 *
 * <p>
 * There are a number of scenarios where an error may occur, for example:
 * <ul>
 * <li>The response or assertion request is missing or malformed</li>
 * <li>Missing or invalid subject</li>
 * <li>Missing or invalid signatures</li>
 * <li>The time period validation for the assertion fails</li>
 * <li>One of the assertion conditions was not met</li>
 * <li>Decryption failed</li>
 * <li>Unable to locate a subject identifier, commonly known as username</li>
 * </ul>
 *
 * @since 5.2
 */
public class Saml2AuthenticationException extends AuthenticationException {

	private final Saml2Error error;

	/**
	 * Constructs a {@code Saml2AuthenticationException} using the provided parameters.
	 * @param error the {@link Saml2Error SAML 2.0 Error}
	 */
	public Saml2AuthenticationException(Saml2Error error) {
		this(error, error.getDescription());
	}

	/**
	 * Constructs a {@code Saml2AuthenticationException} using the provided parameters.
	 * @param error the {@link Saml2Error SAML 2.0 Error}
	 * @param cause the root cause
	 */
	public Saml2AuthenticationException(Saml2Error error, Throwable cause) {
		this(error, cause.getMessage(), cause);
	}

	/**
	 * Constructs a {@code Saml2AuthenticationException} using the provided parameters.
	 * @param error the {@link Saml2Error SAML 2.0 Error}
	 * @param message the detail message
	 */
	public Saml2AuthenticationException(Saml2Error error, String message) {
		this(error, message, null);
	}

	/**
	 * Constructs a {@code Saml2AuthenticationException} using the provided parameters.
	 * @param error the {@link Saml2Error SAML 2.0 Error}
	 * @param message the detail message
	 * @param cause the root cause
	 */
	public Saml2AuthenticationException(Saml2Error error, String message, Throwable cause) {
		super(message, cause);
		Assert.notNull(error, "error cannot be null");
		this.error = error;
	}

	/**
	 * Constructs a {@code Saml2AuthenticationException} using the provided parameters.
	 * @param error the
	 * {@link org.springframework.security.saml2.provider.service.authentication.Saml2Error
	 * SAML 2.0 Error}
	 * @deprecated Use
	 * {@link org.springframework.security.saml2.provider.service.authentication.Saml2Error}
	 * constructor instead
	 */
	@Deprecated
	public Saml2AuthenticationException(
			org.springframework.security.saml2.provider.service.authentication.Saml2Error error) {
		this(error, error.getDescription());
	}

	/**
	 * Constructs a {@code Saml2AuthenticationException} using the provided parameters.
	 * @param error the
	 * {@link org.springframework.security.saml2.provider.service.authentication.Saml2Error
	 * SAML 2.0 Error}
	 * @param cause the root cause
	 * @deprecated Use
	 * {@link org.springframework.security.saml2.provider.service.authentication.Saml2Error}
	 * constructor instead
	 */
	@Deprecated
	public Saml2AuthenticationException(
			org.springframework.security.saml2.provider.service.authentication.Saml2Error error, Throwable cause) {
		this(error, cause.getMessage(), cause);
	}

	/**
	 * Constructs a {@code Saml2AuthenticationException} using the provided parameters.
	 * @param error the {@link Saml2Error SAML 2.0 Error}
	 * @param message the detail message
	 * @deprecated Use {@link Saml2Error} constructor instead
	 */
	@Deprecated
	public Saml2AuthenticationException(
			org.springframework.security.saml2.provider.service.authentication.Saml2Error error, String message) {
		this(error, message, null);
	}

	/**
	 * Constructs a {@code Saml2AuthenticationException} using the provided parameters.
	 * @param error the
	 * {@link org.springframework.security.saml2.provider.service.authentication.Saml2Error
	 * SAML 2.0 Error}
	 * @param message the detail message
	 * @param cause the root cause
	 * @deprecated Use
	 * {@link org.springframework.security.saml2.provider.service.authentication.Saml2Error}
	 * constructor instead
	 */
	@Deprecated
	public Saml2AuthenticationException(
			org.springframework.security.saml2.provider.service.authentication.Saml2Error error, String message,
			Throwable cause) {
		super(message, cause);
		Assert.notNull(error, "error cannot be null");
		this.error = new Saml2Error(error.getErrorCode(), error.getDescription());
	}

	/**
	 * Get the associated {@link Saml2Error}
	 * @return the associated {@link Saml2Error}
	 */
	public Saml2Error getSaml2Error() {
		return this.error;
	}

	/**
	 * Returns the {@link Saml2Error SAML 2.0 Error}.
	 * @return the {@link Saml2Error}
	 * @deprecated Use {@link #getSaml2Error()} instead
	 */
	@Deprecated
	public org.springframework.security.saml2.provider.service.authentication.Saml2Error getError() {
		return new org.springframework.security.saml2.provider.service.authentication.Saml2Error(
				this.error.getErrorCode(), this.error.getDescription());
	}

	@Override
	public String toString() {
		final StringBuffer sb = new StringBuffer("Saml2AuthenticationException{");
		sb.append("error=").append(this.error);
		sb.append('}');
		return sb.toString();
	}

}
