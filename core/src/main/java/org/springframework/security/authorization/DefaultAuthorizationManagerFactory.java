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
 * @author Andrey Litvitski
 * @since 7.0
 */
public final class DefaultAuthorizationManagerFactory<T extends @Nullable Object>
		implements AuthorizationManagerFactory<T> {

	private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

	private RoleHierarchy roleHierarchy = new NullRoleHierarchy();

	private String rolePrefix = "ROLE_";

	private String[] requiredAuthorities = new String[0];

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

	/**
	 * Sets authorities required for authorization managers that apply to authenticated
	 * users.
	 * <p>
	 * Does not affect {@code anonymous}, {@code permitAll}, or {@code denyAll}.
	 * <p>
	 * Evaluated with the configured {@link RoleHierarchy}.
	 * @param requiredAuthorities the required authorities (must not be {@code null})
	 */
	public void setRequiredAuthorities(String[] requiredAuthorities) {
		Assert.notNull(requiredAuthorities, "requiredAuthorities cannot be null");
		this.requiredAuthorities = requiredAuthorities;
	}

	/**
	 * Creates a factory that requires the given authorities for authorization managers
	 * that apply to authenticated users.
	 * <p>
	 * Does not affect {@code anonymous}, {@code permitAll}, or {@code denyAll}.
	 * @param authorities the required authorities
	 * @param <T> the secured object type
	 * @return a factory configured with the required authorities
	 */
	public static <T> AuthorizationManagerFactory<T> withAuthorities(String... authorities) {
		DefaultAuthorizationManagerFactory<T> factory = new DefaultAuthorizationManagerFactory<>();
		factory.setRequiredAuthorities(authorities);
		return factory;
	}

	@Override
	public AuthorizationManager<T> hasRole(String role) {
		return hasAnyRole(role);
	}

	@Override
	public AuthorizationManager<T> hasAnyRole(String... roles) {
		return withRequiredAuthorities(
				withRoleHierarchy(AuthorityAuthorizationManager.hasAnyRole(this.rolePrefix, roles)));
	}

	@Override
	public AuthorizationManager<T> hasAllRoles(String... roles) {
		return withRequiredAuthorities(withRoleHierarchy(
				AllAuthoritiesAuthorizationManager.hasAllPrefixedAuthorities(this.rolePrefix, roles)));
	}

	@Override
	public AuthorizationManager<T> hasAuthority(String authority) {
		return withRequiredAuthorities(withRoleHierarchy(AuthorityAuthorizationManager.hasAuthority(authority)));
	}

	@Override
	public AuthorizationManager<T> hasAnyAuthority(String... authorities) {
		return withRequiredAuthorities(withRoleHierarchy(AuthorityAuthorizationManager.hasAnyAuthority(authorities)));
	}

	@Override
	public AuthorizationManager<T> hasAllAuthorities(String... authorities) {
		return withRequiredAuthorities(
				withRoleHierarchy(AllAuthoritiesAuthorizationManager.hasAllAuthorities(authorities)));
	}

	@Override
	public AuthorizationManager<T> authenticated() {
		return withRequiredAuthorities(withTrustResolver(AuthenticatedAuthorizationManager.authenticated()));
	}

	@Override
	public AuthorizationManager<T> fullyAuthenticated() {
		return withRequiredAuthorities(withTrustResolver(AuthenticatedAuthorizationManager.fullyAuthenticated()));
	}

	@Override
	public AuthorizationManager<T> rememberMe() {
		return withRequiredAuthorities(withTrustResolver(AuthenticatedAuthorizationManager.rememberMe()));
	}

	@Override
	public AuthorizationManager<T> anonymous() {
		return withTrustResolver(AuthenticatedAuthorizationManager.anonymous());
	}

	private AuthorityAuthorizationManager<T> withRoleHierarchy(AuthorityAuthorizationManager<T> authorizationManager) {
		authorizationManager.setRoleHierarchy(this.roleHierarchy);
		return authorizationManager;
	}

	private AllAuthoritiesAuthorizationManager<T> withRoleHierarchy(
			AllAuthoritiesAuthorizationManager<T> authorizationManager) {
		authorizationManager.setRoleHierarchy(this.roleHierarchy);
		return authorizationManager;
	}

	private AuthenticatedAuthorizationManager<T> withTrustResolver(
			AuthenticatedAuthorizationManager<T> authorizationManager) {
		authorizationManager.setTrustResolver(this.trustResolver);
		return authorizationManager;
	}

	private AuthorizationManager<T> withRequiredAuthorities(AuthorizationManager<T> manager) {
		if (this.requiredAuthorities == null || this.requiredAuthorities.length == 0) {
			return manager;
		}
		AuthorizationManager<T> required = withRoleHierarchy(
				AllAuthoritiesAuthorizationManager.hasAllAuthorities(this.requiredAuthorities));
		return AuthorizationManagers.allOf(new AuthorizationDecision(false), manager, required);
	}

}
