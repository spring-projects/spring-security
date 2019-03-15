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

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.Assert;

/**
 * This exception is thrown for all OAuth 2.0 related {@link Authentication} errors.
 *
 * <p>
 * There are a number of scenarios where an error may occur, for example:
 * <ul>
 *  <li>The authorization request or token request is missing a required parameter</li>
 *	<li>Missing or invalid client identifier</li>
 *	<li>Invalid or mismatching redirection URI</li>
 *	<li>The requested scope is invalid, unknown, or malformed</li>
 *	<li>The resource owner or authorization server denied the access request</li>
 *	<li>Client authentication failed</li>
 *	<li>The provided authorization grant (authorization code, resource owner credentials) is invalid, expired, or revoked</li>
 * </ul>
 *
 * @author Joe Grandja
 * @since 5.0
 */
public class OAuth2AuthenticationException extends AuthenticationException {
	private OAuth2Error error;

	/**
	 * Constructs an {@code OAuth2AuthenticationException} using the provided parameters.
	 *
	 * @param error the {@link OAuth2Error OAuth 2.0 Error}
	 */
	public OAuth2AuthenticationException(OAuth2Error error) {
		this(error, error.getDescription());
	}

	/**
	 * Constructs an {@code OAuth2AuthenticationException} using the provided parameters.
	 *
	 * @param error the {@link OAuth2Error OAuth 2.0 Error}
	 * @param cause the root cause
	 */
	public OAuth2AuthenticationException(OAuth2Error error, Throwable cause) {
		this(error, cause.getMessage(), cause);
	}

	/**
	 * Constructs an {@code OAuth2AuthenticationException} using the provided parameters.
	 *
	 * @param error the {@link OAuth2Error OAuth 2.0 Error}
	 * @param message the detail message
	 */
	public OAuth2AuthenticationException(OAuth2Error error, String message) {
		super(message);
		this.setError(error);
	}

	/**
	 * Constructs an {@code OAuth2AuthenticationException} using the provided parameters.
	 *
	 * @param error the {@link OAuth2Error OAuth 2.0 Error}
	 * @param message the detail message
	 * @param cause the root cause
	 */
	public OAuth2AuthenticationException(OAuth2Error error, String message, Throwable cause) {
		super(message, cause);
		this.setError(error);
	}

	/**
	 * Returns the {@link OAuth2Error OAuth 2.0 Error}.
	 *
	 * @return the {@link OAuth2Error}
	 */
	public OAuth2Error getError() {
		return this.error;
	}

	private void setError(OAuth2Error error) {
		Assert.notNull(error, "error cannot be null");
		this.error = error;
	}
}
