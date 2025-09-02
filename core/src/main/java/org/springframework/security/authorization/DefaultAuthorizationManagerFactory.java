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

import org.springframework.security.access.hierarchicalroles.NullRoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.util.Assert;

/**
 * A factory for creating different kinds of {@link AuthorizationManager} instances.
 *
 * @param <T> the type of object that the authorization check is being done on
 * @author Steve Riesenberg
 * @since 7.0
 */
public final class DefaultAuthorizationManagerFactory<T extends @Nullable Object>
		implements AuthorizationManagerFactory<T> {

	private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

	private RoleHierarchy roleHierarchy = new NullRoleHierarchy();

	private String rolePrefix = "ROLE_";

	/**
	 * Sets the {@link AuthenticationTrustResolver} used to check the user's
	 * authentication.
	 * @param trustResolver the {@link AuthenticationTrustResolver} to use
	 */
	public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
		Assert.notNull(trustResolver, "trustResolver cannot be null");
		this.trustResolver = trustResolver;
	}

	/**
	 * Sets the {@link RoleHierarchy} used to discover reachable authorities.
	 * @param roleHierarchy the {@link RoleHierarchy} to use
	 */
	public void setRoleHierarchy(RoleHierarchy roleHierarchy) {
		Assert.notNull(roleHierarchy, "roleHierarchy cannot be null");
		this.roleHierarchy = roleHierarchy;
	}

	/**
	 * Sets the prefix used to create an authority name from a role name. Can be an empty
	 * string.
	 * @param rolePrefix the role prefix to use
	 */
	public void setRolePrefix(String rolePrefix) {
		Assert.notNull(rolePrefix, "rolePrefix cannot be null");
		this.rolePrefix = rolePrefix;
	}

	@Override
	public AuthorizationManager<T> hasRole(String role) {
		return hasAnyRole(role);
	}

	@Override
	public AuthorizationManager<T> hasAnyRole(String... roles) {
		return withRoleHierarchy(AuthorityAuthorizationManager.hasAnyRole(this.rolePrefix, roles));
	}

	@Override
	public AuthorizationManager<T> hasAuthority(String authority) {
		return withRoleHierarchy(AuthorityAuthorizationManager.hasAuthority(authority));
	}

	@Override
	public AuthorizationManager<T> hasAnyAuthority(String... authorities) {
		return withRoleHierarchy(AuthorityAuthorizationManager.hasAnyAuthority(authorities));
	}

	@Override
	public AuthorizationManager<T> authenticated() {
		return withTrustResolver(AuthenticatedAuthorizationManager.authenticated());
	}

	@Override
	public AuthorizationManager<T> fullyAuthenticated() {
		return withTrustResolver(AuthenticatedAuthorizationManager.fullyAuthenticated());
	}

	@Override
	public AuthorizationManager<T> rememberMe() {
		return withTrustResolver(AuthenticatedAuthorizationManager.rememberMe());
	}

	@Override
	public AuthorizationManager<T> anonymous() {
		return withTrustResolver(AuthenticatedAuthorizationManager.anonymous());
	}

	private AuthorityAuthorizationManager<T> withRoleHierarchy(AuthorityAuthorizationManager<T> authorizationManager) {
		authorizationManager.setRoleHierarchy(this.roleHierarchy);
		return authorizationManager;
	}

	private AuthenticatedAuthorizationManager<T> withTrustResolver(
			AuthenticatedAuthorizationManager<T> authorizationManager) {
		authorizationManager.setTrustResolver(this.trustResolver);
		return authorizationManager;
	}

}
