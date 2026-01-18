/*
 * Copyright 2025-present the original author or authors.
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

package org.springframework.security.oauth2.core.authorization;

import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;
import org.springframework.util.Assert;

/**
 * A factory for creating different kinds of {@link AuthorizationManager} instances.
 *
 * @param <T> the type of object that the authorization check is being done on
 * @author Ngoc Nhan
 * @since 7.1
 */
public final class DefaultOAuth2AuthorizationManagerFactory<T> implements OAuth2AuthorizationManagerFactory<T> {

	private String scopePrefix = "SCOPE_";

	private final AuthorizationManagerFactory<T> authorizationManagerFactory;

	public DefaultOAuth2AuthorizationManagerFactory() {
		this(new DefaultAuthorizationManagerFactory<>());
	}

	public DefaultOAuth2AuthorizationManagerFactory(AuthorizationManagerFactory<T> authorizationManagerFactory) {
		Assert.notNull(authorizationManagerFactory, "authorizationManagerFactory can not be null");
		this.authorizationManagerFactory = authorizationManagerFactory;
	}

	/**
	 * Sets the prefix used to create an authority name from a scope name. Can be an empty
	 * string.
	 * @param scopePrefix the scope prefix to use
	 */
	public void setScopePrefix(String scopePrefix) {
		Assert.notNull(scopePrefix, "scopePrefix can not be null");
		this.scopePrefix = scopePrefix;
	}

	@Override
	public AuthorizationManager<T> hasScope(String scope) {
		Assert.notNull(scope, "scope can not be null");
		assertScope(scope);
		return this.authorizationManagerFactory.hasAuthority(this.scopePrefix + scope);
	}

	@Override
	public AuthorizationManager<T> hasAnyScope(String... scopes) {
		return this.authorizationManagerFactory.hasAnyAuthority(this.mappedScopes(scopes));
	}

	@Override
	public AuthorizationManager<T> hasAllScopes(String... scopes) {
		return this.authorizationManagerFactory.hasAllAuthorities(this.mappedScopes(scopes));
	}

	private String[] mappedScopes(String... scopes) {
		Assert.notNull(scopes, "scopes can not be null");
		String[] mappedScopes = new String[scopes.length];
		for (int i = 0; i < scopes.length; i++) {
			assertScope(scopes[i]);
			mappedScopes[i] = this.scopePrefix + scopes[i];
		}
		return mappedScopes;
	}

	private void assertScope(String scope) {
		Assert.isTrue(!scope.startsWith(this.scopePrefix), () -> scope + " should not start with '" + this.scopePrefix
				+ "' since '" + this.scopePrefix
				+ "' is automatically prepended when using hasScope and hasAnyScope. Consider using AuthorizationManagerFactory#hasAuthority or #hasAnyAuthority instead.");
	}

}
