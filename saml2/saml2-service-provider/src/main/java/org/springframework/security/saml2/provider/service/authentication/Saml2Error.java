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

import java.io.Serializable;

import org.springframework.security.core.SpringSecurityCoreVersion;

/**
 * A representation of an SAML 2.0 Error.
 *
 * <p>
 * At a minimum, an error response will contain an error code.
 * The commonly used error code are defined in this class
 * or a new codes can be defined in the future as arbitrary strings.
 * </p>
 * @since 5.2
 * @deprecated Use {@link org.springframework.security.saml2.core.Saml2Error} instead
 */
@Deprecated
public class Saml2Error implements Serializable {
	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final org.springframework.security.saml2.core.Saml2Error error;

	/**
	 * Constructs a {@code Saml2Error} using the provided parameters.
	 *
	 * @param errorCode the error code
	 * @param description the error description
	 */
	public Saml2Error(String errorCode, String description) {
		this.error = new org.springframework.security.saml2.core.Saml2Error(errorCode, description);
	}

	/**
	 * Returns the error code.
	 *
	 * @return the error code
	 */
	public final String getErrorCode() {
		return this.error.getErrorCode();
	}

	/**
	 * Returns the error description.
	 *
	 * @return the error description
	 */
	public final String getDescription() {
		return this.error.getDescription();
	}

	@Override
	public String toString() {
		return "[" + this.getErrorCode() + "] " +
				(this.getDescription() != null ? this.getDescription() : "");
	}
}
