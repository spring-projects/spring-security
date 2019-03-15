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
package org.springframework.security.oauth2.core;

/**
 * Base exception for OAuth 2.0 Authorization errors.
 *
 * @author Joe Grandja
 * @since 5.1
 */
public class OAuth2AuthorizationException extends RuntimeException {
	private OAuth2Error error;

	/**
	 * Constructs an {@code OAuth2AuthorizationException} using the provided parameters.
	 *
	 * @param error the {@link OAuth2Error OAuth 2.0 Error}
	 */
	public OAuth2AuthorizationException(OAuth2Error error) {
		super(error.toString());
		this.error = error;
	}

	/**
	 * Constructs an {@code OAuth2AuthorizationException} using the provided parameters.
	 *
	 * @param error the {@link OAuth2Error OAuth 2.0 Error}
	 * @param cause the root cause
	 */
	public OAuth2AuthorizationException(OAuth2Error error, Throwable cause) {
		super(error.toString(), cause);
		this.error = error;
	}

	/**
	 * Returns the {@link OAuth2Error OAuth 2.0 Error}.
	 *
	 * @return the {@link OAuth2Error}
	 */
	public OAuth2Error getError() {
		return this.error;
	}
}
