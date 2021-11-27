/*
 * Copyright 2002-2018 the original author or authors.
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
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.util.Assert;

/**
 * A representation of a
 * <a href="https://tools.ietf.org/html/rfc6750#section-3.1" target="_blank">Bearer Token
 * Error</a>.
 *
 * @author Vedran Pavic
 * @author Josh Cummings
 * @since 5.1
 * @see BearerTokenErrorCodes
 * @see <a href="https://tools.ietf.org/html/rfc6750#section-3" target="_blank">RFC 6750
 * Section 3: The WWW-Authenticate Response Header Field</a>
 */
public final class BearerTokenError extends OAuth2Error {

	private final HttpStatus httpStatus;

	private final String scope;

	/**
	 * Create a {@code BearerTokenError} using the provided parameters
	 * @param errorCode the error code
	 * @param httpStatus the HTTP status
	 */
	public BearerTokenError(String errorCode, HttpStatus httpStatus, String description, String errorUri) {
		this(errorCode, httpStatus, description, errorUri, null);
	}

	/**
	 * Create a {@code BearerTokenError} using the provided parameters
	 * @param errorCode the error code
	 * @param httpStatus the HTTP status
	 * @param description the description
	 * @param errorUri the URI
	 * @param scope the scope
	 */
	public BearerTokenError(String errorCode, HttpStatus httpStatus, String description, String errorUri,
			String scope) {
		super(errorCode, description, errorUri);
		Assert.notNull(httpStatus, "httpStatus cannot be null");
		Assert.isTrue(isDescriptionValid(description),
				"description contains invalid ASCII characters, it must conform to RFC 6750");
		Assert.isTrue(isErrorCodeValid(errorCode),
				"errorCode contains invalid ASCII characters, it must conform to RFC 6750");
		Assert.isTrue(isErrorUriValid(errorUri),
				"errorUri contains invalid ASCII characters, it must conform to RFC 6750");
		Assert.isTrue(isScopeValid(scope), "scope contains invalid ASCII characters, it must conform to RFC 6750");
		this.httpStatus = httpStatus;
		this.scope = scope;
	}

	/**
	 * Return the HTTP status.
	 * @return the HTTP status
	 */
	public HttpStatus getHttpStatus() {
		return this.httpStatus;
	}

	/**
	 * Return the scope.
	 * @return the scope
	 */
	public String getScope() {
		return this.scope;
	}

	private static boolean isDescriptionValid(String description) {
		// @formatter:off
		return description == null || description.chars().allMatch((c) ->
				withinTheRangeOf(c, 0x20, 0x21) ||
				withinTheRangeOf(c, 0x23, 0x5B) ||
				withinTheRangeOf(c, 0x5D, 0x7E));
		// @formatter:on
	}

	private static boolean isErrorCodeValid(String errorCode) {
		// @formatter:off
		return errorCode.chars().allMatch((c) ->
				withinTheRangeOf(c, 0x20, 0x21) ||
				withinTheRangeOf(c, 0x23, 0x5B) ||
				withinTheRangeOf(c, 0x5D, 0x7E));
		// @formatter:on
	}

	private static boolean isErrorUriValid(String errorUri) {
		return errorUri == null || errorUri.chars()
				.allMatch((c) -> c == 0x21 || withinTheRangeOf(c, 0x23, 0x5B) || withinTheRangeOf(c, 0x5D, 0x7E));
	}

	private static boolean isScopeValid(String scope) {
		// @formatter:off
		return scope == null || scope.chars().allMatch((c) ->
				withinTheRangeOf(c, 0x20, 0x21) ||
				withinTheRangeOf(c, 0x23, 0x5B) ||
				withinTheRangeOf(c, 0x5D, 0x7E));
		// @formatter:on
	}

	private static boolean withinTheRangeOf(int c, int min, int max) {
		return c >= min && c <= max;
	}

}
