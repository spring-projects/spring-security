/*
 * Copyright 2002-2022 the original author or authors.
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

/**
 * Standard error codes defined by the OAuth 2.0 Authorization Framework: Bearer Token
 * Usage.
 *
 * @author Vedran Pavic
 * @since 5.1
 * @see <a href="https://tools.ietf.org/html/rfc6750#section-3.1" target="_blank">RFC 6750
 * Section 3.1: Error Codes</a>
 */
public final class BearerTokenErrorCodes {

	/**
	 * {@code invalid_request} - The request is missing a required parameter, includes an
	 * unsupported parameter or parameter value, repeats the same parameter, uses more
	 * than one method for including an access token, or is otherwise malformed.
	 */
	public static final String INVALID_REQUEST = "invalid_request";

	/**
	 * {@code invalid_token} - The access token provided is expired, revoked, malformed,
	 * or invalid for other reasons.
	 */
	public static final String INVALID_TOKEN = "invalid_token";

	/**
	 * {@code insufficient_scope} - The request requires higher privileges than provided
	 * by the access token.
	 */
	public static final String INSUFFICIENT_SCOPE = "insufficient_scope";

	private BearerTokenErrorCodes() {
	}

}
