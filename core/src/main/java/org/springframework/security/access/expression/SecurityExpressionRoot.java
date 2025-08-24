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
import java.util.function.Supplier;

import org.jspecify.annotations.Nullable;

import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.function.SingletonSupplier;

/**
 * Base root object for use in Spring Security expression evaluations.
 *
 * @author Luke Taylor
 * @author Evgeniy Cheban
 * @author Steve Riesenberg
 * @since 3.0
 */
public abstract class SecurityExpressionRoot<T extends @Nullable Object> implements SecurityExpressionOperations {

	private final Supplier<Authentication> authentication;

	private String defaultRolePrefix = "ROLE_";

	private final T object;

	private AuthorizationManagerFactory<T> authorizationManagerFactory = new DefaultAuthorizationManagerFactory<>();

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
	 * @deprecated Use {@link #SecurityExpressionRoot(Supplier, Object)} instead
	 */
	@Deprecated(since = "7.0")
	@SuppressWarnings("NullAway")
	public SecurityExpressionRoot(@Nullable Authentication authentication) {
		this(() -> authentication, null);
	}

	/**
	 * Creates a new instance that uses lazy initialization of the {@link Authentication}
	 * object.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to use.
	 * Cannot be null.
	 * @since 5.8
	 * @deprecated Use {@link #SecurityExpressionRoot(Supplier, Object)} instead
	 */
	@Deprecated(since = "7.0")
	@SuppressWarnings("NullAway")
	public SecurityExpressionRoot(Supplier<@Nullable Authentication> authentication) {
		this(authentication, null);
	}

	/**
	 * Creates a new instance that uses lazy initialization of the {@link Authentication}
	 * object.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to use.
	 * Cannot be null.
	 * @param object the object being authorized
	 * @since 7.0
	 */
	public SecurityExpressionRoot(Supplier<? extends @Nullable Authentication> authentication, T object) {
		this.authentication = SingletonSupplier.of(() -> {
			Authentication value = authentication.get();
			Assert.notNull(value, "Authentication object cannot be null");
			return value;
		});
		this.object = object;
	}

	@Override
	public final boolean hasAuthority(String authority) {
		return isGranted(this.authorizationManagerFactory.hasAnyAuthority(authority));
	}

	@Override
	public final boolean hasAnyAuthority(String... authorities) {
		return isGranted(this.authorizationManagerFactory.hasAnyAuthority(authorities));
	}

	public final boolean hasAllAuthorities(String... authorities) {
		AuthorizationManager<T> manager = this.authorizationManagerFactory.hasAllAuthorities(authorities);
		return isGranted(manager);
	}

	@Override
	public final boolean hasRole(String role) {
		if (this.authorizationManagerFactory instanceof DefaultAuthorizationManagerFactory<T>) {
			// To provide passivity for old behavior where hasRole('ROLE_A') is allowed,
			// we strip the role prefix when found.
			// TODO: Remove in favor of fixing inconsistent behavior?
			String rolePrefix = this.defaultRolePrefix;
			if (role.startsWith(rolePrefix)) {
				role = role.substring(rolePrefix.length());
			}
		}
		return isGranted(this.authorizationManagerFactory.hasRole(role));
	}

	@Override
	public final boolean hasAnyRole(String... roles) {
		if (this.authorizationManagerFactory instanceof DefaultAuthorizationManagerFactory<T>) {
			// To provide passivity for old behavior where hasRole('ROLE_A') is allowed,
			// we strip the role prefix when found.
			// TODO: Remove in favor of fixing inconsistent behavior?
			String rolePrefix = this.defaultRolePrefix;
			for (int index = 0; index < roles.length; index++) {
				String role = roles[index];
				if (role.startsWith(rolePrefix)) {
					roles[index] = role.substring(rolePrefix.length());
				}
			}
		}
		return isGranted(this.authorizationManagerFactory.hasAnyRole(roles));
	}

	public final boolean hasAllRoles(String... roles) {
		AuthorizationManager<T> manager = this.authorizationManagerFactory.hasAllRoles(roles);
		return isGranted(manager);
	}

	@Override
	public final Authentication getAuthentication() {
		return this.authentication.get();
	}

	@Override
	public final boolean permitAll() {
		return isGranted(this.authorizationManagerFactory.permitAll());
	}

	@Override
	public final boolean denyAll() {
		return isGranted(this.authorizationManagerFactory.denyAll());
	}

	@Override
	public final boolean isAnonymous() {
		return isGranted(this.authorizationManagerFactory.anonymous());
	}

	@Override
	public final boolean isAuthenticated() {
		return isGranted(this.authorizationManagerFactory.authenticated());
	}

	@Override
	public final boolean isRememberMe() {
		return isGranted(this.authorizationManagerFactory.rememberMe());
	}

	@Override
	public final boolean isFullyAuthenticated() {
		return isGranted(this.authorizationManagerFactory.fullyAuthenticated());
	}

	private boolean isGranted(AuthorizationManager<T> authorizationManager) {
		AuthorizationResult authorizationResult = authorizationManager.authorize(this.authentication, this.object);
		return (authorizationResult != null && authorizationResult.isGranted());
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

	/**
	 * @deprecated Use
	 * {@link #setAuthorizationManagerFactory(AuthorizationManagerFactory)} instead
	 */
	@Deprecated(since = "7.0")
	public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
		getDefaultAuthorizationManagerFactory().setTrustResolver(trustResolver);
	}

	/**
	 * @deprecated Use
	 * {@link #setAuthorizationManagerFactory(AuthorizationManagerFactory)} instead
	 */
	@Deprecated(since = "7.0")
	public void setRoleHierarchy(@Nullable RoleHierarchy roleHierarchy) {
		if (roleHierarchy != null) {
			getDefaultAuthorizationManagerFactory().setRoleHierarchy(roleHierarchy);
		}
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
	 * @deprecated Use
	 * {@link #setAuthorizationManagerFactory(AuthorizationManagerFactory)} instead
	 */
	@Deprecated(since = "7.0")
	public void setDefaultRolePrefix(@Nullable String defaultRolePrefix) {
		if (defaultRolePrefix == null) {
			defaultRolePrefix = "";
		}
		getDefaultAuthorizationManagerFactory().setRolePrefix(defaultRolePrefix);
		this.defaultRolePrefix = defaultRolePrefix;
	}

	/**
	 * Sets the {@link AuthorizationManagerFactory} to use for creating instances of
	 * {@link AuthorizationManager}.
	 * @param authorizationManagerFactory the {@link AuthorizationManagerFactory} to use
	 * @since 7.0
	 */
	public void setAuthorizationManagerFactory(AuthorizationManagerFactory<T> authorizationManagerFactory) {
		Assert.notNull(authorizationManagerFactory, "authorizationManagerFactory cannot be null");
		this.authorizationManagerFactory = authorizationManagerFactory;
	}

	/**
	 * Allows accessing the {@link DefaultAuthorizationManagerFactory} for getting and
	 * setting defaults. This method will be removed in Spring Security 8.
	 * @return the {@link DefaultAuthorizationManagerFactory}
	 * @throws IllegalStateException if a different {@link AuthorizationManagerFactory}
	 * was already set
	 * @deprecated Use
	 * {@link #setAuthorizationManagerFactory(AuthorizationManagerFactory)} instead
	 */
	@Deprecated(since = "7.0", forRemoval = true)
	private DefaultAuthorizationManagerFactory<T> getDefaultAuthorizationManagerFactory() {
		if (!(this.authorizationManagerFactory instanceof DefaultAuthorizationManagerFactory<T> defaultAuthorizationManagerFactory)) {
			throw new IllegalStateException(
					"authorizationManagerFactory must be an instance of DefaultAuthorizationManagerFactory");
		}

		return defaultAuthorizationManagerFactory;
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

}
