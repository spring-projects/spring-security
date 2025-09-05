/*
 * Copyright 2020-2021 the original author or authors.
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

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * This exception is thrown by
 * {@link OAuth2AuthorizationCodeRequestAuthenticationProvider} when an attempt to
 * authenticate the OAuth 2.0 Authorization Request (or Consent) fails.
 *
 * @author Joe Grandja
 * @since 0.1.2
 * @see OAuth2AuthorizationCodeRequestAuthenticationToken
 * @see OAuth2AuthorizationCodeRequestAuthenticationProvider
 */
public class OAuth2AuthorizationCodeRequestAuthenticationException extends OAuth2AuthenticationException {

	private final OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication;

	/**
	 * Constructs an {@code OAuth2AuthorizationCodeRequestAuthenticationException} using
	 * the provided parameters.
	 * @param error the {@link OAuth2Error OAuth 2.0 Error}
	 * @param authorizationCodeRequestAuthentication the {@link Authentication} instance
	 * of the OAuth 2.0 Authorization Request (or Consent)
	 */
	public OAuth2AuthorizationCodeRequestAuthenticationException(OAuth2Error error,
			@Nullable OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication) {
		super(error);
		this.authorizationCodeRequestAuthentication = authorizationCodeRequestAuthentication;
	}

	/**
	 * Constructs an {@code OAuth2AuthorizationCodeRequestAuthenticationException} using
	 * the provided parameters.
	 * @param error the {@link OAuth2Error OAuth 2.0 Error}
	 * @param cause the root cause
	 * @param authorizationCodeRequestAuthentication the {@link Authentication} instance
	 * of the OAuth 2.0 Authorization Request (or Consent)
	 */
	public OAuth2AuthorizationCodeRequestAuthenticationException(OAuth2Error error, Throwable cause,
			@Nullable OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication) {
		super(error, cause);
		this.authorizationCodeRequestAuthentication = authorizationCodeRequestAuthentication;
	}

	/**
	 * Returns the {@link Authentication} instance of the OAuth 2.0 Authorization Request
	 * (or Consent), or {@code null} if not available.
	 * @return the {@link OAuth2AuthorizationCodeRequestAuthenticationToken}
	 */
	@Nullable
	public OAuth2AuthorizationCodeRequestAuthenticationToken getAuthorizationCodeRequestAuthentication() {
		return this.authorizationCodeRequestAuthentication;
	}

}
