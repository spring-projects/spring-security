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

package org.springframework.security.oauth2.server.resource;

import org.springframework.http.HttpStatus;

/**
 * A factory for creating {@link BearerTokenError} instances that correspond to the
 * registered <a href="https://tools.ietf.org/html/rfc6750#section-3.1">Bearer Token Error
 * Codes</a>.
 *
 * @author Josh Cummings
 * @since 5.3
 */
public final class BearerTokenErrors {

	private static final BearerTokenError DEFAULT_INVALID_REQUEST = invalidRequest("Invalid request");

	private static final BearerTokenError DEFAULT_INVALID_TOKEN = invalidToken("Invalid token");

	private static final BearerTokenError DEFAULT_INSUFFICIENT_SCOPE = insufficientScope("Insufficient scope", null);

	private static final String DEFAULT_URI = "https://tools.ietf.org/html/rfc6750#section-3.1";

	private BearerTokenErrors() {
	}

	/**
	 * Create a {@link BearerTokenError} caused by an invalid request
	 * @param message a description of the error
	 * @return a {@link BearerTokenError}
	 */
	public static BearerTokenError invalidRequest(String message) {
		try {
			return new BearerTokenError(BearerTokenErrorCodes.INVALID_REQUEST, HttpStatus.BAD_REQUEST, message,
					DEFAULT_URI);
		}
		catch (IllegalArgumentException ex) {
			// some third-party library error messages are not suitable for RFC 6750's
			// error message charset
			return DEFAULT_INVALID_REQUEST;
		}
	}

	/**
	 * Create a {@link BearerTokenError} caused by an invalid token
	 * @param message a description of the error
	 * @return a {@link BearerTokenError}
	 */
	public static BearerTokenError invalidToken(String message) {
		try {
			return new BearerTokenError(BearerTokenErrorCodes.INVALID_TOKEN, HttpStatus.UNAUTHORIZED, message,
					DEFAULT_URI);
		}
		catch (IllegalArgumentException ex) {
			// some third-party library error messages are not suitable for RFC 6750's
			// error message charset
			return DEFAULT_INVALID_TOKEN;
		}
	}

	/**
	 * Create a {@link BearerTokenError} caused by an invalid token
	 * @param scope the scope attribute to use in the error
	 * @return a {@link BearerTokenError}
	 */
	public static BearerTokenError insufficientScope(String message, String scope) {
		try {
			return new BearerTokenError(BearerTokenErrorCodes.INSUFFICIENT_SCOPE, HttpStatus.FORBIDDEN, message,
					DEFAULT_URI, scope);
		}
		catch (IllegalArgumentException ex) {
			// some third-party library error messages are not suitable for RFC 6750's
			// error message charset
			return DEFAULT_INSUFFICIENT_SCOPE;
		}
	}

}
