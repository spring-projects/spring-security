/*
 * Copyright 2002-present the original author or authors.
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

package org.springframework.security.authorization;

import org.jspecify.annotations.Nullable;

/**
 * A factory for creating different kinds of {@link AuthorizationManager} instances.
 *
 * @param <T> the type of object that the authorization check is being done on
 * @author Steve Riesenberg
 * @since 7.0
 */
public interface AuthorizationManagerFactory<T extends @Nullable Object> {

	/**
	 * Create an {@link AuthorizationManager} that allows anyone.
	 * @return A new {@link AuthorizationManager} instance
	 */
	default AuthorizationManager<T> permitAll() {
		return SingleResultAuthorizationManager.permitAll();
	}

	/**
	 * Creates an {@link AuthorizationManager} that does not allow anyone.
	 * @return A new {@link AuthorizationManager} instance
	 */
	default AuthorizationManager<T> denyAll() {
		return SingleResultAuthorizationManager.denyAll();
	}

	/**
	 * Creates an {@link AuthorizationManager} that requires users to have the specified
	 * role.
	 * @param role the role (automatically prepended with ROLE_) that should be required
	 * to allow access (i.e. USER, ADMIN, etc.)
	 * @return A new {@link AuthorizationManager} instance
	 */
	default AuthorizationManager<T> hasRole(String role) {
		return AuthorityAuthorizationManager.hasRole(role);
	}

	/**
	 * Creates an {@link AuthorizationManager} that requires users to have one of many
	 * roles.
	 * @param roles the roles (automatically prepended with ROLE_) that the user should
	 * have at least one of to allow access (i.e. USER, ADMIN, etc.)
	 * @return A new {@link AuthorizationManager} instance
	 */
	default AuthorizationManager<T> hasAnyRole(String... roles) {
		return AuthorityAuthorizationManager.hasAnyRole(roles);
	}

	/**
	 * Creates an {@link AuthorizationManager} that requires users to have the specified
	 * authority.
	 * @param authority the authority that should be required to allow access (i.e.
	 * ROLE_USER, ROLE_ADMIN, etc.)
	 * @return A new {@link AuthorizationManager} instance
	 */
	default AuthorizationManager<T> hasAuthority(String authority) {
		return AuthorityAuthorizationManager.hasAuthority(authority);
	}

	/**
	 * Creates an {@link AuthorizationManager} that requires users to have one of many
	 * authorities.
	 * @param authorities the authorities that the user should have at least one of to
	 * allow access (i.e. ROLE_USER, ROLE_ADMIN, etc.)
	 * @return A new {@link AuthorizationManager} instance
	 */
	default AuthorizationManager<T> hasAnyAuthority(String... authorities) {
		return AuthorityAuthorizationManager.hasAnyAuthority(authorities);
	}

	/**
	 * Creates an {@link AuthorizationManager} that allows any authenticated user.
	 * @return A new {@link AuthorizationManager} instance
	 */
	default AuthorizationManager<T> authenticated() {
		return AuthenticatedAuthorizationManager.authenticated();
	}

	/**
	 * Creates an {@link AuthorizationManager} that allows users who have authenticated
	 * and were not remembered.
	 * @return A new {@link AuthorizationManager} instance
	 */
	default AuthorizationManager<T> fullyAuthenticated() {
		return AuthenticatedAuthorizationManager.fullyAuthenticated();
	}

	/**
	 * Creates an {@link AuthorizationManager} that allows users that have been
	 * remembered.
	 * @return A new {@link AuthorizationManager} instance
	 */
	default AuthorizationManager<T> rememberMe() {
		return AuthenticatedAuthorizationManager.rememberMe();
	}

	/**
	 * Creates an {@link AuthorizationManager} that allows only anonymous users.
	 * @return A new {@link AuthorizationManager} instance
	 */
	default AuthorizationManager<T> anonymous() {
		return AuthenticatedAuthorizationManager.anonymous();
	}

}
