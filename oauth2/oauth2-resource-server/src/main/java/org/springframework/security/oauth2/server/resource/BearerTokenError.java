/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.server.resource;

import java.io.Serializable;

import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

/**
 * A representation of an Bearer Token Error.
 *
 * @author Vedran Pavic
 * @since 5.1
 * @see BearerTokenErrorCodes
 * @see <a href="https://tools.ietf.org/html/rfc6750#section-3" target="_blank">RFC 6750 Section 3: The WWW-Authenticate Response Header Field</a>
 */
public final class BearerTokenError implements Serializable {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final String errorCode;

	private final String description;

	private final String uri;

	private final String scope;

	/**
	 * Create a {@code BearerTokenError} using the provided parameters.
	 * @param errorCode the error code
	 */
	public BearerTokenError(String errorCode) {
		this(errorCode, null, null, null);
	}

	/**
	 * Create a {@code BearerTokenError} using the provided parameters.
	 * @param errorCode the error code
	 * @param description the description
	 * @param uri the URI
	 * @param scope the scope
	 */
	public BearerTokenError(String errorCode, String description, String uri, String scope) {
		Assert.hasText(errorCode, "errorCode must not be empty");
		this.errorCode = errorCode;
		this.description = description;
		this.uri = uri;
		this.scope = scope;
	}

	/**
	 * Return the error code.
	 * @return the error code
	 */
	public String getErrorCode() {
		return this.errorCode;
	}

	/**
	 * Return the description.
	 * @return the description
	 */
	public String getDescription() {
		return this.description;
	}

	/**
	 * Return the URI.
	 * @return the URI
	 */
	public String getUri() {
		return this.uri;
	}

	/**
	 * Return the scope.
	 * @return the scope
	 */
	public String getScope() {
		return scope;
	}

	@Override
	public String toString() {
		return "[" + this.getErrorCode() + "]" + (this.description != null ? " " + this.description : "");
	}

}
