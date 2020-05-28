/*
 * Copyright 2002-2016 the original author or authors.
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

import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import reactor.core.publisher.Mono;

import java.io.Serializable;
import java.util.Collection;
import java.util.Set;

/**
 * Base root object for use in Spring Security expression evaluations.
 *
 * @author Luke Taylor
 * @author Sheiy
 * @since 5.4
 */
public abstract class SecurityExpressionReactiveRoot implements SecurityExpressionReactiveOperations {
	protected final Mono<Authentication> authentication;
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
	 *
	 * @param authentication the {@link Authentication} to use. Cannot be null.
	 */
	public SecurityExpressionReactiveRoot(Mono<Authentication> authentication) {
		if (authentication == null) {
			throw new IllegalArgumentException("Authentication object cannot be null");
		}
		this.authentication = authentication;
	}

	public final Mono<Boolean> hasAuthority(String authority) {
		return hasAnyAuthority(authority);
	}

	public final Mono<Boolean> hasAnyAuthority(String... authorities) {
		return hasAnyAuthorityName(null, authorities);
	}

	public final Mono<Boolean> hasRole(String role) {
		return hasAnyRole(role);
	}

	public final Mono<Boolean> hasAnyRole(String... roles) {
		return hasAnyAuthorityName(defaultRolePrefix, roles);
	}

	private Mono<Boolean> hasAnyAuthorityName(String prefix, String... roles) {
		return getAuthoritySet().map(roleSet -> {
			for (String role : roles) {
				String defaultedRole = getRoleWithDefaultPrefix(prefix, role);
				if (roleSet.contains(defaultedRole)) {
					return true;
				}
			}
			return false;
		});
	}

	public final Mono<Authentication> getAuthentication() {
		return authentication;
	}

	public final Mono<Boolean> permitAll() {
		return Mono.just(true);
	}

	public final Mono<Boolean> denyAll() {
		return Mono.just(false);
	}

	public final Mono<Boolean> isAnonymous() {
		return authentication.map(auth -> trustResolver.isAnonymous(auth));
	}

	public final Mono<Boolean> isAuthenticated() {
		return isAnonymous().map(aBoolean -> !aBoolean);
	}

	public final Mono<Boolean> isRememberMe() {
		return authentication.map(auth -> trustResolver.isRememberMe(auth));
	}

	public final Mono<Boolean> isFullyAuthenticated() {
		return authentication.map(auth -> {
			return !trustResolver.isAnonymous(auth)
					&& !trustResolver.isRememberMe(auth);
		});
	}

	/**
	 * Convenience method to access {@link Authentication#getPrincipal()} from
	 * {@link #getAuthentication()}
	 *
	 * @return
	 */
	public Mono<Object> getPrincipal() {
		return authentication.map(auth -> auth.getPrincipal());
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
	 *
	 * @param defaultRolePrefix the default prefix to add to roles. Default "ROLE_".
	 */
	public void setDefaultRolePrefix(String defaultRolePrefix) {
		this.defaultRolePrefix = defaultRolePrefix;
	}

	private Mono<Set<String>> getAuthoritySet() {
		if (roles == null) {
			return authentication.map(auth -> {
				Collection<? extends GrantedAuthority> userAuthorities = auth
						.getAuthorities();
				if (roleHierarchy != null) {
					userAuthorities = roleHierarchy
							.getReachableGrantedAuthorities(userAuthorities);
				}
				roles = AuthorityUtils.authorityListToSet(userAuthorities);
				return roles;
			});
		}
		return Mono.just(roles);
	}

	public Mono<Boolean> hasPermission(Object target, Object permission) {
		return authentication.map(auth -> permissionEvaluator.hasPermission(auth, target, permission));
	}

	public Mono<Boolean> hasPermission(Object targetId, String targetType, Object permission) {
		return authentication.map(auth -> permissionEvaluator.hasPermission(auth, (Serializable) targetId, targetType, permission));
	}

	public void setPermissionEvaluator(PermissionEvaluator permissionEvaluator) {
		this.permissionEvaluator = permissionEvaluator;
	}

	/**
	 * Prefixes role with defaultRolePrefix if defaultRolePrefix is non-null and if role
	 * does not already start with defaultRolePrefix.
	 *
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
}
