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
import org.springframework.security.core.Authentication;

/**
 * A factory for creating different kinds of {@link AuthorizationManager} instances.
 *
 * @param <T> the type of object that the authorization check is being done on
 * @author Ngoc Nhan
 * @since 7.1
 */
public interface OAuth2AuthorizationManagerFactory<T> {

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
	 * @return an {@link AuthorizationManager} that requires a {@code "SCOPE_scope"}
	 * authority
	 */
	default AuthorizationManager<T> hasScope(String scope) {
		return OAuth2AuthorizationManagers.hasScope(scope);
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
	 * @return an {@link AuthorizationManager} that requires at least one authority among
	 * {@code "SCOPE_scope1"}, {@code SCOPE_scope2}, ... {@code SCOPE_scopeN}.
	 */
	default AuthorizationManager<T> hasAnyScope(String... scopes) {
		return OAuth2AuthorizationManagers.hasAnyScope(scopes);
	}

	/**
	 * Create an {@link AuthorizationManager} that requires an {@link Authentication} to
	 * have all authorities {@code SCOPE_scope1}, {@code SCOPE_scope2}, ...
	 * {@code SCOPE_scopeN}.
	 *
	 * <p>
	 * For example, if you call {@code hasAllScopes("read", "write")}, then each
	 * {@link org.springframework.security.core.Authentication} must have all
	 * {@link org.springframework.security.core.GrantedAuthority} values of
	 * {@code SCOPE_read} and {@code SCOPE_write}.
	 *
	 * <p>
	 * This would be equivalent to calling
	 * {@code AllAuthoritiesAuthorizationManager#hasAllAuthorities("SCOPE_read", "SCOPE_write")}.
	 * @param scopes the scope values to require
	 * @return an {@link AuthorizationManager} that requires all authorities
	 * {@code SCOPE_scope1}, {@code SCOPE_scope2}, ... {@code SCOPE_scopeN}.
	 */
	default AuthorizationManager<T> hasAllScopes(String... scopes) {
		return OAuth2AuthorizationManagers.hasAllScopes(scopes);
	}

}
