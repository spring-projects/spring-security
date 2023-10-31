/*
 * Copyright 2002-2022 the original author or authors.
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

import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.util.Assert;

/**
 * Base root object for use in Spring Security expression evaluations.
 *
 * @author Luke Taylor
 * @author Evgeniy Cheban
 * @since 3.0
 */
public abstract class SecurityExpressionRoot implements SecurityExpressionOperations {

	private final Supplier<Authentication> authentication;

	private AuthenticationTrustResolver trustResolver;

	private RoleHierarchy roleHierarchy;

	private Set<String> roles;

	private String defaultRolePrefix = "ROLE_";

	/**
	 * Allows "permitAll" expression
	 */
	public final boolean permitAll = true;

	/**
	 * Allows "denyAll" expression
	 */
	public final boolean denyAll = false;

	private PermissionEvaluator permissionEvaluator;

	public final String read = "read";

	public final String write = "write";

	public final String create = "create";

	public final String delete = "delete";

	public final String admin = "administration";

	/**
	 * Creates a new instance
	 * @param authentication the {@link Authentication} to use. Cannot be null.
	 */
	public SecurityExpressionRoot(Authentication authentication) {
		this(() -> authentication);
	}

	/**
	 * Creates a new instance that uses lazy initialization of the {@link Authentication}
	 * object.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to use.
	 * Cannot be null.
	 * @since 5.8
	 */
	public SecurityExpressionRoot(Supplier<Authentication> authentication) {
		this.authentication = new AuthenticationSupplier(authentication);
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

	private boolean hasAnyAuthorityName(String prefix, String... roles) {
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
		return !isAnonymous();
	}

	@Override
	public final boolean isRememberMe() {
		return this.trustResolver.isRememberMe(getAuthentication());
	}

	@Override
	public final boolean isFullyAuthenticated() {
		Authentication authentication = getAuthentication();
		return !this.trustResolver.isAnonymous(authentication) && !this.trustResolver.isRememberMe(authentication);
	}

	/**
	 * Convenience method to access {@link Authentication#getPrincipal()} from
	 * {@link #getAuthentication()}
	 * @return
	 */
	public Object getPrincipal() {
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
		this.permissionEvaluator = permissionEvaluator;
	}

	/**
	 * Prefixes role with defaultRolePrefix if defaultRolePrefix is non-null and if role
	 * does not already start with defaultRolePrefix.
	 * @param defaultRolePrefix
	 * @param role
	 * @return
	 */
	private static String getRoleWithDefaultPrefix(String defaultRolePrefix, String role) {
		if (role == null) {
			return role;
		}
		if (defaultRolePrefix == null || defaultRolePrefix.length() == 0) {
			return role;
		}
		if (role.startsWith(defaultRolePrefix)) {
			return role;
		}
		return defaultRolePrefix + role;
	}

	private static final class AuthenticationSupplier implements Supplier<Authentication> {

		private Authentication value;

		private final Supplier<Authentication> delegate;

		private AuthenticationSupplier(Supplier<Authentication> delegate) {
			Assert.notNull(delegate, "delegate cannot be null");
			this.delegate = delegate;
		}

		@Override
		public Authentication get() {
			if (this.value == null) {
				Authentication authentication = this.delegate.get();
				Assert.notNull(authentication, "Authentication object cannot be null");
				this.value = authentication;
			}
			return this.value;
		}

	}

}
