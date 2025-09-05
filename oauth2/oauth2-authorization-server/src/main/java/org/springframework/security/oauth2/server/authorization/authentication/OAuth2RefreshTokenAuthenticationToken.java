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

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

/**
 * An {@link Authentication} implementation used for the OAuth 2.0 Refresh Token Grant.
 *
 * @author Alexey Nesterov
 * @since 0.0.3
 * @see OAuth2AuthorizationGrantAuthenticationToken
 * @see OAuth2RefreshTokenAuthenticationProvider
 */
public class OAuth2RefreshTokenAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

	private final String refreshToken;

	private final Set<String> scopes;

	/**
	 * Constructs an {@code OAuth2RefreshTokenAuthenticationToken} using the provided
	 * parameters.
	 * @param refreshToken the refresh token
	 * @param clientPrincipal the authenticated client principal
	 * @param scopes the requested scope(s)
	 * @param additionalParameters the additional parameters
	 */
	public OAuth2RefreshTokenAuthenticationToken(String refreshToken, Authentication clientPrincipal,
			@Nullable Set<String> scopes, @Nullable Map<String, Object> additionalParameters) {
		super(AuthorizationGrantType.REFRESH_TOKEN, clientPrincipal, additionalParameters);
		Assert.hasText(refreshToken, "refreshToken cannot be empty");
		this.refreshToken = refreshToken;
		this.scopes = Collections.unmodifiableSet((scopes != null) ? new HashSet<>(scopes) : Collections.emptySet());
	}

	/**
	 * Returns the refresh token.
	 * @return the refresh token
	 */
	public String getRefreshToken() {
		return this.refreshToken;
	}

	/**
	 * Returns the requested scope(s).
	 * @return the requested scope(s), or an empty {@code Set} if not available
	 */
	public Set<String> getScopes() {
		return this.scopes;
	}

}
