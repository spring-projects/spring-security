/*
 * Copyright 2002-2025 the original author or authors.
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
public abstract class SecurityExpressionRoot<T> implements SecurityExpressionOperations {

	private static final AuthorizationManagerFactory<?> DEFAULT_AUTHORIZATION_MANAGER_FACTORY = new DefaultAuthorizationManagerFactory<>();

	private final Supplier<Authentication> authentication;

	private final @Nullable T object;

	private @Nullable DefaultAuthorizationManagerFactory<T> defaultAuthorizationManagerFactory;

	private AuthorizationManagerFactory<T> authorizationManagerFactory = defaultAuthorizationManagerFactory();

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
	 * @deprecated use {@link #SecurityExpressionRoot(Supplier, Object)} instead
	 */
	@Deprecated(since = "7.0")
	public SecurityExpressionRoot(Authentication authentication) {
		this(() -> authentication);
	}

	/**
	 * Creates a new instance that uses lazy initialization of the {@link Authentication}
	 * object.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to use.
	 * Cannot be null.
	 * @since 5.8
	 * @deprecated use {@link #SecurityExpressionRoot(Supplier, Object)} instead
	 */
	@Deprecated(since = "7.0")
	public SecurityExpressionRoot(Supplier<Authentication> authentication) {
		this.authentication = SingletonSupplier.of(() -> {
			Authentication value = authentication.get();
			Assert.notNull(value, "Authentication object cannot be null");
			return value;
		});
		this.object = null;
	}

	/**
	 * Creates a new instance that uses lazy initialization of the {@link Authentication}
	 * object.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to use.
	 * Cannot be null.
	 * @param object the object being authorized
	 * @since 7.0
	 */
	public SecurityExpressionRoot(Supplier<Authentication> authentication, T object) {
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

	@Override
	public final boolean hasRole(String role) {
		return isGranted(this.authorizationManagerFactory.hasRole(role));
	}

	@Override
	public final boolean hasAnyRole(String... roles) {
		return isGranted(this.authorizationManagerFactory.hasAnyRole(roles));
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

	@SuppressWarnings("DataFlowIssue")
	private boolean isGranted(AuthorizationManager<T> authorizationManager) {
		AuthorizationResult authorizationResult = authorizationManager.authorize(this.authentication, this.object);
		return (authorizationResult != null && authorizationResult.isGranted());
	}

	/**
	 * Convenience method to access {@link Authentication#getPrincipal()} from
	 * {@link #getAuthentication()}
	 * @return
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
	public void setRoleHierarchy(RoleHierarchy roleHierarchy) {
		getDefaultAuthorizationManagerFactory().setRoleHierarchy(roleHierarchy);
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
	public void setDefaultRolePrefix(String defaultRolePrefix) {
		getDefaultAuthorizationManagerFactory().setRolePrefix(defaultRolePrefix);
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

	private DefaultAuthorizationManagerFactory<T> getDefaultAuthorizationManagerFactory() {
		if (this.defaultAuthorizationManagerFactory == null) {
			this.defaultAuthorizationManagerFactory = new DefaultAuthorizationManagerFactory<>();
			this.authorizationManagerFactory = this.defaultAuthorizationManagerFactory;
		}

		return this.defaultAuthorizationManagerFactory;
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

	@SuppressWarnings("unchecked")
	private static <T> AuthorizationManagerFactory<T> defaultAuthorizationManagerFactory() {
		return (AuthorizationManagerFactory<T>) DEFAULT_AUTHORIZATION_MANAGER_FACTORY;
	}

}
