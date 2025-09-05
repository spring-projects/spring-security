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

import java.util.Map;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

/**
 * An {@link Authentication} implementation used for the OAuth 2.0 Authorization Code
 * Grant.
 *
 * @author Joe Grandja
 * @author Madhu Bhat
 * @author Daniel Garnier-Moiroux
 * @since 0.0.1
 * @see OAuth2AuthorizationGrantAuthenticationToken
 * @see OAuth2AuthorizationCodeAuthenticationProvider
 */
public class OAuth2AuthorizationCodeAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

	private final String code;

	private final String redirectUri;

	/**
	 * Constructs an {@code OAuth2AuthorizationCodeAuthenticationToken} using the provided
	 * parameters.
	 * @param code the authorization code
	 * @param clientPrincipal the authenticated client principal
	 * @param redirectUri the redirect uri
	 * @param additionalParameters the additional parameters
	 */
	public OAuth2AuthorizationCodeAuthenticationToken(String code, Authentication clientPrincipal,
			@Nullable String redirectUri, @Nullable Map<String, Object> additionalParameters) {
		super(AuthorizationGrantType.AUTHORIZATION_CODE, clientPrincipal, additionalParameters);
		Assert.hasText(code, "code cannot be empty");
		this.code = code;
		this.redirectUri = redirectUri;
	}

	/**
	 * Returns the authorization code.
	 * @return the authorization code
	 */
	public String getCode() {
		return this.code;
	}

	/**
	 * Returns the redirect uri.
	 * @return the redirect uri
	 */
	@Nullable
	public String getRedirectUri() {
		return this.redirectUri;
	}

}
