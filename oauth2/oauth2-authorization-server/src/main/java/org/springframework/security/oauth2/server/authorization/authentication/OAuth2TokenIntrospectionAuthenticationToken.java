/*
 * Copyright 2020-2025 the original author or authors.
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

import java.io.Serial;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.util.Assert;

/**
 * An {@link Authentication} implementation used for OAuth 2.0 Token Introspection.
 *
 * @author Gerardo Roza
 * @author Joe Grandja
 * @since 0.1.1
 * @see AbstractAuthenticationToken
 * @see OAuth2TokenIntrospection
 * @see OAuth2TokenIntrospectionAuthenticationProvider
 */
public class OAuth2TokenIntrospectionAuthenticationToken extends AbstractAuthenticationToken {

	@Serial
	private static final long serialVersionUID = 9003173975452760956L;

	private final String token;

	private final Authentication clientPrincipal;

	private final String tokenTypeHint;

	private final Map<String, Object> additionalParameters;

	private final OAuth2TokenIntrospection tokenClaims;

	/**
	 * Constructs an {@code OAuth2TokenIntrospectionAuthenticationToken} using the
	 * provided parameters.
	 * @param token the token
	 * @param clientPrincipal the authenticated client principal
	 * @param tokenTypeHint the token type hint
	 * @param additionalParameters the additional parameters
	 */
	public OAuth2TokenIntrospectionAuthenticationToken(String token, Authentication clientPrincipal,
			@Nullable String tokenTypeHint, @Nullable Map<String, Object> additionalParameters) {
		super(Collections.emptyList());
		Assert.hasText(token, "token cannot be empty");
		Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
		this.token = token;
		this.clientPrincipal = clientPrincipal;
		this.tokenTypeHint = tokenTypeHint;
		this.additionalParameters = Collections.unmodifiableMap(
				(additionalParameters != null) ? new HashMap<>(additionalParameters) : Collections.emptyMap());
		this.tokenClaims = OAuth2TokenIntrospection.builder().build();
	}

	/**
	 * Constructs an {@code OAuth2TokenIntrospectionAuthenticationToken} using the
	 * provided parameters.
	 * @param token the token
	 * @param clientPrincipal the authenticated client principal
	 * @param tokenClaims the token claims
	 */
	public OAuth2TokenIntrospectionAuthenticationToken(String token, Authentication clientPrincipal,
			OAuth2TokenIntrospection tokenClaims) {
		super(Collections.emptyList());
		Assert.hasText(token, "token cannot be empty");
		Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
		Assert.notNull(tokenClaims, "tokenClaims cannot be null");
		this.token = token;
		this.clientPrincipal = clientPrincipal;
		this.tokenTypeHint = null;
		this.additionalParameters = Collections.emptyMap();
		this.tokenClaims = tokenClaims;
		// Indicates that the request was authenticated, even though the token might not
		// be active
		setAuthenticated(true);
	}

	@Override
	public Object getPrincipal() {
		return this.clientPrincipal;
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	/**
	 * Returns the token.
	 * @return the token
	 */
	public String getToken() {
		return this.token;
	}

	/**
	 * Returns the token type hint.
	 * @return the token type hint
	 */
	@Nullable
	public String getTokenTypeHint() {
		return this.tokenTypeHint;
	}

	/**
	 * Returns the additional parameters.
	 * @return the additional parameters
	 */
	public Map<String, Object> getAdditionalParameters() {
		return this.additionalParameters;
	}

	/**
	 * Returns the token claims.
	 * @return the {@link OAuth2TokenIntrospection}
	 */
	public OAuth2TokenIntrospection getTokenClaims() {
		return this.tokenClaims;
	}

}
