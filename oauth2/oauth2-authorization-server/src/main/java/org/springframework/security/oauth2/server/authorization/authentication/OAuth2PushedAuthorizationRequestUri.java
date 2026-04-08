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

package org.springframework.security.oauth2.server.authorization.authentication;

import java.time.Instant;
import java.util.Base64;

import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;

/**
 * A representation of a {@code request_uri} used in OAuth 2.0 Pushed Authorization
 * Requests.
 *
 * @author Joe Grandja
 * @since 7.0
 */
final class OAuth2PushedAuthorizationRequestUri {

	private static final String REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:";

	private static final String REQUEST_URI_DELIMITER = "___";

	private static final StringKeyGenerator DEFAULT_STATE_GENERATOR = new Base64StringKeyGenerator(
			Base64.getUrlEncoder());

	private final String requestUri;

	private final String state;

	private final Instant expiresAt;

	static OAuth2PushedAuthorizationRequestUri create() {
		return create(Instant.now().plusSeconds(300));
	}

	static OAuth2PushedAuthorizationRequestUri create(Instant expiresAt) {
		String state = DEFAULT_STATE_GENERATOR.generateKey();
		String requestUri = REQUEST_URI_PREFIX + state + REQUEST_URI_DELIMITER + expiresAt.toEpochMilli();
		state = state + REQUEST_URI_DELIMITER + expiresAt.toEpochMilli();
		return new OAuth2PushedAuthorizationRequestUri(requestUri, state, expiresAt);
	}

	static OAuth2PushedAuthorizationRequestUri parse(String requestUri) {
		int stateStartIndex = REQUEST_URI_PREFIX.length();
		int expiresAtStartIndex = requestUri.indexOf(REQUEST_URI_DELIMITER) + REQUEST_URI_DELIMITER.length();
		String state = requestUri.substring(stateStartIndex);
		Instant expiresAt = Instant.ofEpochMilli(Long.parseLong(requestUri.substring(expiresAtStartIndex)));
		return new OAuth2PushedAuthorizationRequestUri(requestUri, state, expiresAt);
	}

	String getRequestUri() {
		return this.requestUri;
	}

	String getState() {
		return this.state;
	}

	Instant getExpiresAt() {
		return this.expiresAt;
	}

	private OAuth2PushedAuthorizationRequestUri(String requestUri, String state, Instant expiresAt) {
		this.requestUri = requestUri;
		this.state = state;
		this.expiresAt = expiresAt;
	}

}
