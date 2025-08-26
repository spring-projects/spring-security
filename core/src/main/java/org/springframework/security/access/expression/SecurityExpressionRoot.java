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

package org.springframework.security.access.expression;

import java.io.Serializable;
import java.util.Collection;
import java.util.Set;
import java.util.function.Supplier;

import org.jspecify.annotations.Nullable;

import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.util.function.SingletonSupplier;

/**
 * Base root object for use in Spring Security expression evaluations.
 *
 * @author Luke Taylor
 * @author Evgeniy Cheban
 * @author Ngoc Nhan
 * @since 3.0
 */
public abstract class SecurityExpressionRoot implements SecurityExpressionOperations {

	private final Supplier<Authentication> authentication;

	private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

	private @Nullable RoleHierarchy roleHierarchy;

	private @Nullable Set<String> roles;

	private String defaultRolePrefix = "ROLE_";

	/**
	 * Allows "permitAll" expression
	 */
	public final boolean permitAll = true;

	/**
	 * Allows "denyAll" expression
	 */
	public final boolean denyAll = false;

	private PermissionEvaluator permissionEvaluator = new DenyAllPermissionEvaluator();

	public final String read = "read";

	public final String write = "write";

	public final String create = "create";

	public final String delete = "delete";

	public final String admin = "administration";

	/**
	 * Creates a new instance
	 * @param authentication the {@link Authentication} to use. Cannot be null.
	 */
	public SecurityExpressionRoot(@Nullable Authentication authentication) {
		this(() -> authentication);
	}

	/**
	 * Creates a new instance that uses lazy initialization of the {@link Authentication}
	 * object.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to use.
	 * Cannot be null.
	 * @since 5.8
	 */
	public SecurityExpressionRoot(Supplier<@Nullable Authentication> authentication) {
		this.authentication = SingletonSupplier.of(() -> {
			Authentication value = authentication.get();
			Assert.notNull(value, "Authentication object cannot be null");
			return value;
		});
	}

	@Override
	public final boolean hasAuthority(String authority) {
		return hasAnyAuthority(authority);
	}

	@Override
	public final boolean hasAnyAuthority(String... authorities) {
		return hasAnyAuthorityName(null, authorities);
	}

	@Override
	public final boolean hasRole(String role) {
		return hasAnyRole(role);
	}

	@Override
	public final boolean hasAnyRole(String... roles) {
		return hasAnyAuthorityName(this.defaultRolePrefix, roles);
	}

	private boolean hasAnyAuthorityName(@Nullable String prefix, String... roles) {
		Set<String> roleSet = getAuthoritySet();
		for (String role : roles) {
			String defaultedRole = getRoleWithDefaultPrefix(prefix, role);
			if (roleSet.contains(defaultedRole)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public final Authentication getAuthentication() {
		return this.authentication.get();
	}

	@Override
	public final boolean permitAll() {
		return true;
	}

	@Override
	public final boolean denyAll() {
		return false;
	}

	@Override
	public final boolean isAnonymous() {
		return this.trustResolver.isAnonymous(getAuthentication());
	}

	@Override
	public final boolean isAuthenticated() {
		return this.trustResolver.isAuthenticated(getAuthentication());
	}

	@Override
	public final boolean isRememberMe() {
		return this.trustResolver.isRememberMe(getAuthentication());
	}

	@Override
	public final boolean isFullyAuthenticated() {
		Authentication authentication = getAuthentication();
		return this.trustResolver.isFullyAuthenticated(authentication);
	}

	/**
	 * Convenience method to access {@link Authentication#getPrincipal()} from
	 * {@link #getAuthentication()}
	 * @return the <code>Principal</code> being authenticated or the authenticated
	 * principal after authentication.
	 */
	public @Nullable Object getPrincipal() {
		return getAuthentication().getPrincipal();
	}

	public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
		this.trustResolver = trustResolver;
	}

	public void setRoleHierarchy(RoleHierarchy roleHierarchy) {
		this.roleHierarchy = roleHierarchy;
	}

	/**
	 * <p>
	 * Sets the default prefix to be added to {@link #hasAnyRole(String...)} or
	 * {@link #hasRole(String)}. For example, if hasRole("ADMIN") or hasRole("ROLE_ADMIN")
	 * is passed in, then the role ROLE_ADMIN will be used when the defaultRolePrefix is
	 * "ROLE_" (default).
	 * </p>
	 *
	 * <p>
	 * If null or empty, then no default role prefix is used.
	 * </p>
	 * @param defaultRolePrefix the default prefix to add to roles. Default "ROLE_".
	 */
	public void setDefaultRolePrefix(String defaultRolePrefix) {
		this.defaultRolePrefix = defaultRolePrefix;
	}

	private Set<String> getAuthoritySet() {
		if (this.roles == null) {
			Collection<? extends GrantedAuthority> userAuthorities = getAuthentication().getAuthorities();
			if (this.roleHierarchy != null) {
				userAuthorities = this.roleHierarchy.getReachableGrantedAuthorities(userAuthorities);
			}
			this.roles = AuthorityUtils.authorityListToSet(userAuthorities);
		}
		return this.roles;
	}

	@Override
	public boolean hasPermission(Object target, Object permission) {
		return this.permissionEvaluator.hasPermission(getAuthentication(), target, permission);
	}

	@Override
	public boolean hasPermission(Object targetId, String targetType, Object permission) {
		return this.permissionEvaluator.hasPermission(getAuthentication(), (Serializable) targetId, targetType,
				permission);
	}

	public void setPermissionEvaluator(PermissionEvaluator permissionEvaluator) {
		Assert.notNull(permissionEvaluator, "permissionEvaluator cannot be null");
		this.permissionEvaluator = permissionEvaluator;
	}

	/**
	 * Prefixes role with defaultRolePrefix if defaultRolePrefix is non-null and if role
	 * does not already start with defaultRolePrefix.
	 * @param defaultRolePrefix the default prefix to add to roles.
	 * @param role the role that should be required.
	 * @return a {@code String} role
	 */
	private static String getRoleWithDefaultPrefix(@Nullable String defaultRolePrefix, String role) {
		if (role == null) {
			return role;
		}
		if (!StringUtils.hasLength(defaultRolePrefix)) {
			return role;
		}
		if (role.startsWith(defaultRolePrefix)) {
			return role;
		}
		return defaultRolePrefix + role;
	}

}
