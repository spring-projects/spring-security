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
 * @author Rob Winch
 * @since 7.0
 */
public final class DefaultAuthorizationManagerFactory<T extends @Nullable Object>
		implements AuthorizationManagerFactory<T> {

	private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

	private RoleHierarchy roleHierarchy = new NullRoleHierarchy();

	private String rolePrefix = "ROLE_";

	private @Nullable AuthorizationManager<T> additionalAuthorization;

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
	 * Sets additional authorization to be applied to the returned
	 * {@link AuthorizationManager} for the following methods:
	 *
	 * <ul>
	 * <li>{@link #hasRole(String)}</li>
	 * <li>{@link #hasAnyRole(String...)}</li>
	 * <li>{@link #hasAllRoles(String...)}</li>
	 * <li>{@link #hasAuthority(String)}</li>
	 * <li>{@link #hasAnyAuthority(String...)}</li>
	 * <li>{@link #hasAllAuthorities(String...)}</li>
	 * <li>{@link #authenticated()}</li>
	 * <li>{@link #fullyAuthenticated()}</li>
	 * <li>{@link #rememberMe()}</li>
	 * </ul>
	 *
	 * <p>
	 * This does not affect {@code anonymous}, {@code permitAll}, or {@code denyAll}.
	 * </p>
	 * @param additionalAuthorization the {@link AuthorizationManager} to be applied.
	 * Default is null (no additional authorization).
	 */
	public void setAdditionalAuthorization(@Nullable AuthorizationManager<T> additionalAuthorization) {
		this.additionalAuthorization = additionalAuthorization;
	}

	@Override
	public AuthorizationManager<T> hasRole(String role) {
		return hasAnyRole(role);
	}

	@Override
	public AuthorizationManager<T> hasAnyRole(String... roles) {
		return createManager(AuthorityAuthorizationManager.hasAnyRole(this.rolePrefix, roles));
	}

	@Override
	public AuthorizationManager<T> hasAllRoles(String... roles) {
		return createManager(AllAuthoritiesAuthorizationManager.hasAllPrefixedAuthorities(this.rolePrefix, roles));
	}

	@Override
	public AuthorizationManager<T> hasAuthority(String authority) {
		return createManager(AuthorityAuthorizationManager.hasAuthority(authority));
	}

	@Override
	public AuthorizationManager<T> hasAnyAuthority(String... authorities) {
		return createManager(AuthorityAuthorizationManager.hasAnyAuthority(authorities));
	}

	@Override
	public AuthorizationManager<T> hasAllAuthorities(String... authorities) {
		return createManager(AllAuthoritiesAuthorizationManager.hasAllAuthorities(authorities));
	}

	@Override
	public AuthorizationManager<T> authenticated() {
		return createManager(AuthenticatedAuthorizationManager.authenticated());
	}

	@Override
	public AuthorizationManager<T> fullyAuthenticated() {
		return createManager(AuthenticatedAuthorizationManager.fullyAuthenticated());
	}

	@Override
	public AuthorizationManager<T> rememberMe() {
		return createManager(AuthenticatedAuthorizationManager.rememberMe());
	}

	@Override
	public AuthorizationManager<T> anonymous() {
		return createManager(AuthenticatedAuthorizationManager.anonymous());
	}

	private AuthorizationManager<T> createManager(AuthorityAuthorizationManager<T> authorizationManager) {
		authorizationManager.setRoleHierarchy(this.roleHierarchy);
		return withAdditionalAuthorization(authorizationManager);
	}

	private AuthorizationManager<T> createManager(AllAuthoritiesAuthorizationManager<T> authorizationManager) {
		authorizationManager.setRoleHierarchy(this.roleHierarchy);
		return withAdditionalAuthorization(authorizationManager);
	}

	private AuthorizationManager<T> createManager(AuthenticatedAuthorizationManager<T> authorizationManager) {
		authorizationManager.setTrustResolver(this.trustResolver);
		return withAdditionalAuthorization(authorizationManager);
	}

	private AuthorizationManager<T> withAdditionalAuthorization(AuthorizationManager<T> manager) {
		if (this.additionalAuthorization == null) {
			return manager;
		}
		return AuthorizationManagers.allOf(new AuthorizationDecision(false), this.additionalAuthorization, manager);
	}

}
