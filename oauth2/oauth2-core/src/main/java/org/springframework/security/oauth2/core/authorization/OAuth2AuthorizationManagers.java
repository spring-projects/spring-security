/*
 * Copyright 2002-2023 the original author or authors.
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

import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * A convenience class for creating OAuth 2.0-specific {@link AuthorizationManager}s.
 *
 * @author Mario Petrovski
 * @author Josh Cummings
 * @since 6.2
 * @see AuthorityAuthorizationManager
 */
public final class OAuth2AuthorizationManagers {

	private OAuth2AuthorizationManagers() {
	}

	/**
	 * Create an {@link AuthorizationManager} that requires an {@link Authentication} to
	 * have a {@code SCOPE_scope} authority.
	 *
	 * <p>
	 * For example, if you call {@code hasScope("read")}, then this will require that each
	 * authentication have a {@link org.springframework.security.core.GrantedAuthority}
	 * whose value is {@code SCOPE_read}.
	 *
	 * <p>
	 * This would equivalent to calling
	 * {@code AuthorityAuthorizationManager#hasAuthority("SCOPE_read")}.
	 * @param scope the scope value to require
	 * @param <T> the secure object
	 * @return an {@link AuthorizationManager} that requires a {@code "SCOPE_scope"}
	 * authority
	 */
	public static <T> AuthorizationManager<T> hasScope(String scope) {
		assertScope(scope);
		return AuthorityAuthorizationManager.hasAuthority("SCOPE_" + scope);
	}

	/**
	 * Create an {@link AuthorizationManager} that requires an {@link Authentication} to
	 * have at least one authority among {@code SCOPE_scope1}, {@code SCOPE_scope2}, ...
	 * {@code SCOPE_scopeN}.
	 *
	 * <p>
	 * For example, if you call {@code hasAnyScope("read", "write")}, then this will
	 * require that each authentication have at least a
	 * {@link org.springframework.security.core.GrantedAuthority} whose value is either
	 * {@code SCOPE_read} or {@code SCOPE_write}.
	 *
	 * <p>
	 * This would equivalent to calling
	 * {@code AuthorityAuthorizationManager#hasAnyAuthority("SCOPE_read", "SCOPE_write")}.
	 * @param scopes the scope values to allow
	 * @param <T> the secure object
	 * @return an {@link AuthorizationManager} that requires at least one authority among
	 * {@code "SCOPE_scope1"}, {@code SCOPE_scope2}, ... {@code SCOPE_scopeN}.
	 *
	 */
	public static <T> AuthorizationManager<T> hasAnyScope(String... scopes) {
		String[] mappedScopes = new String[scopes.length];
		for (int i = 0; i < scopes.length; i++) {
			assertScope(scopes[i]);
			mappedScopes[i] = "SCOPE_" + scopes[i];
		}
		return AuthorityAuthorizationManager.hasAnyAuthority(mappedScopes);
	}

	private static void assertScope(String scope) {
		Assert.isTrue(!scope.startsWith("SCOPE_"),
				() -> scope + " should not start with SCOPE_ since SCOPE_"
						+ " is automatically prepended when using hasScope and hasAnyScope. Consider using "
						+ " AuthorityAuthorizationManager#hasAuthority or #hasAnyAuthority instead.");
	}

}
