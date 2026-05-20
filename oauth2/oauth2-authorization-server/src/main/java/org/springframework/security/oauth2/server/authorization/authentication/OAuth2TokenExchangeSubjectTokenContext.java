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

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * The context returned by an {@link OAuth2TokenExchangeSubjectTokenResolver} containing
 * the resolved principal and claims from the subject token.
 *
 * @author Bapuji Koraganti
 * @since 7.0
 * @see OAuth2TokenExchangeSubjectTokenResolver
 */
public final class OAuth2TokenExchangeSubjectTokenContext {

	private final Authentication principal;

	private final String principalName;

	private final Map<String, Object> claims;

	private final Set<String> scopes;

	/**
	 * Constructs an {@code OAuth2TokenExchangeSubjectTokenContext} using the provided
	 * parameters.
	 * @param principal the authenticated principal resolved from the subject token
	 * @param principalName the principal name (e.g., the {@code sub} claim)
	 * @param claims the claims extracted from the subject token
	 * @param scopes the scopes associated with the subject token
	 */
	public OAuth2TokenExchangeSubjectTokenContext(Authentication principal, String principalName,
			Map<String, Object> claims, Set<String> scopes) {
		Assert.notNull(principal, "principal cannot be null");
		Assert.hasText(principalName, "principalName cannot be empty");
		Assert.notNull(claims, "claims cannot be null");
		Assert.notNull(scopes, "scopes cannot be null");
		this.principal = principal;
		this.principalName = principalName;
		this.claims = Collections.unmodifiableMap(claims);
		this.scopes = Collections.unmodifiableSet(scopes);
	}

	/**
	 * Returns the authenticated principal resolved from the subject token.
	 * @return the authenticated principal
	 */
	public Authentication getPrincipal() {
		return this.principal;
	}

	/**
	 * Returns the principal name (e.g., the {@code sub} claim from an ID token).
	 * @return the principal name
	 */
	public String getPrincipalName() {
		return this.principalName;
	}

	/**
	 * Returns the claims extracted from the subject token.
	 * @return the claims
	 */
	public Map<String, Object> getClaims() {
		return this.claims;
	}

	/**
	 * Returns the scopes associated with the subject token.
	 * @return the scopes
	 */
	public Set<String> getScopes() {
		return this.scopes;
	}

}
