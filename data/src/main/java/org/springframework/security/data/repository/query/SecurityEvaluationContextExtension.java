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

package org.springframework.security.data.repository.query;

import org.jspecify.annotations.Nullable;

import org.springframework.data.spel.spi.EvaluationContextExtension;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.DenyAllPermissionEvaluator;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.hierarchicalroles.NullRoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.Assert;

/**
 * <p>
 * By defining this object as a Bean, Spring Security is exposed as SpEL expressions for
 * creating Spring Data queries.
 *
 * <p>
 * With Java based configuration, we can define the bean using the following:
 *
 * <p>
 * For example, if you return a UserDetails that extends the following User object:
 *
 * <pre>
 * &#064;Entity
 * public class User {
 *     &#064;GeneratedValue(strategy = GenerationType.AUTO)
 *     &#064;Id
 *     private Long id;
 *
 *     ...
 * }
 * </pre>
 *
 * <p>
 * And you have a Message object that looks like the following:
 *
 * <pre>
 * &#064;Entity
 * public class Message {
 *     &#064;Id
 *     &#064;GeneratedValue(strategy = GenerationType.AUTO)
 *     private Long id;
 *
 *     &#064;OneToOne
 *     private User to;
 *
 *     ...
 * }
 * </pre>
 *
 * You can use the following {@code Query} annotation to search for only messages that are
 * to the current user:
 *
 * <pre>
 * &#064;Repository
 * public interface SecurityMessageRepository extends MessageRepository {
 *
 * 	&#064;Query(&quot;select m from Message m where m.to.id = ?#{ principal?.id }&quot;)
 * 	List&lt;Message&gt; findAll();
 * }
 * </pre>
 *
 * This works because the principal in this instance is a User which has an id field on
 * it.
 *
 * @author Rob Winch
 * @author Evgeniy Cheban
 * @since 4.0
 */
public class SecurityEvaluationContextExtension implements EvaluationContextExtension {

	private static final String DEFAULT_ROLE_PREFIX = "ROLE_";

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
		.getContextHolderStrategy();

	private @Nullable Authentication authentication;

	private AuthorizationManagerFactory<Object> authorizationManagerFactory = new DefaultAuthorizationManagerFactory<>();

	private PermissionEvaluator permissionEvaluator = new DenyAllPermissionEvaluator();

	private String defaultRolePrefix = DEFAULT_ROLE_PREFIX;

	/**
	 * Creates a new instance that uses the current {@link Authentication} found on the
	 * {@link org.springframework.security.core.context.SecurityContextHolder}.
	 */
	public SecurityEvaluationContextExtension() {
	}

	/**
	 * Creates a new instance that always uses the same {@link Authentication} object.
	 * @param authentication the {@link Authentication} to use
	 */
	public SecurityEvaluationContextExtension(@Nullable Authentication authentication) {
		this.authentication = authentication;
	}

	@Override
	public String getExtensionId() {
		return "security";
	}

	@Override
	public SecurityExpressionRoot<Object> getRootObject() {
		Authentication authentication = getAuthentication();
		SecurityExpressionRoot<Object> root = new SecurityExpressionRoot<>(() -> authentication, new Object()) {
		};
		root.setAuthorizationManagerFactory(this.authorizationManagerFactory);
		root.setPermissionEvaluator(this.permissionEvaluator);
		if (!DEFAULT_ROLE_PREFIX.equals(this.defaultRolePrefix)) {
			// Ensure SecurityExpressionRoot can strip the custom role prefix
			root.setDefaultRolePrefix(this.defaultRolePrefix);
		}
		return root;
	}

	/**
	 * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
	 * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
	 * @param securityContextHolderStrategy the {@link SecurityContextHolderStrategy} to
	 * use. Cannot be null.
	 * @since 5.8
	 */
	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

	private @Nullable Authentication getAuthentication() {
		if (this.authentication != null) {
			return this.authentication;
		}
		SecurityContext context = this.securityContextHolderStrategy.getContext();
		return context.getAuthentication();
	}

	/**
	 * Sets the {@link AuthorizationManagerFactory} to be used. The default is
	 * {@link DefaultAuthorizationManagerFactory}.
	 * @param authorizationManagerFactory the {@link AuthorizationManagerFactory} to use.
	 * Cannot be null.
	 * @since 7.0
	 */
	public void setAuthorizationManagerFactory(AuthorizationManagerFactory<Object> authorizationManagerFactory) {
		Assert.notNull(authorizationManagerFactory, "authorizationManagerFactory cannot be null");
		this.authorizationManagerFactory = authorizationManagerFactory;
	}

	/**
	 * Allows accessing the {@link DefaultAuthorizationManagerFactory} for getting and
	 * setting defaults. This method will be removed in Spring Security 8.
	 * @return the {@link DefaultAuthorizationManagerFactory}
	 * @throws IllegalStateException if a different {@link AuthorizationManagerFactory}
	 * was already set
	 */
	private DefaultAuthorizationManagerFactory<Object> getDefaultAuthorizationManagerFactory() {
		if (!(this.authorizationManagerFactory instanceof DefaultAuthorizationManagerFactory<Object> defaultAuthorizationManagerFactory)) {
			throw new IllegalStateException(
					"authorizationManagerFactory must be an instance of DefaultAuthorizationManagerFactory");
		}

		return defaultAuthorizationManagerFactory;
	}

	/**
	 * Sets the {@link AuthenticationTrustResolver} to be used. Default is
	 * {@link AuthenticationTrustResolverImpl}. Cannot be null.
	 * @param trustResolver the {@link AuthenticationTrustResolver} to use
	 * @since 5.8
	 * @deprecated Use
	 * {@link #setAuthorizationManagerFactory(AuthorizationManagerFactory)} instead
	 */
	@Deprecated(since = "7.0")
	public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
		Assert.notNull(trustResolver, "trustResolver cannot be null");
		getDefaultAuthorizationManagerFactory().setTrustResolver(trustResolver);
	}

	/**
	 * Sets the {@link RoleHierarchy} to be used. Default is {@link NullRoleHierarchy}.
	 * Cannot be null.
	 * @param roleHierarchy the {@link RoleHierarchy} to use
	 * @since 5.8
	 * @deprecated Use
	 * {@link #setAuthorizationManagerFactory(AuthorizationManagerFactory)} instead
	 */
	@Deprecated(since = "7.0")
	public void setRoleHierarchy(RoleHierarchy roleHierarchy) {
		Assert.notNull(roleHierarchy, "roleHierarchy cannot be null");
		getDefaultAuthorizationManagerFactory().setRoleHierarchy(roleHierarchy);
	}

	/**
	 * Sets the {@link PermissionEvaluator} to be used. Default is
	 * {@link DenyAllPermissionEvaluator}. Cannot be null.
	 * @param permissionEvaluator the {@link PermissionEvaluator} to use
	 * @since 5.8
	 */
	public void setPermissionEvaluator(PermissionEvaluator permissionEvaluator) {
		Assert.notNull(permissionEvaluator, "permissionEvaluator cannot be null");
		this.permissionEvaluator = permissionEvaluator;
	}

	/**
	 * Sets the default prefix to be added to
	 * {@link org.springframework.security.access.expression.SecurityExpressionRoot#hasAnyRole(String...)}
	 * or
	 * {@link org.springframework.security.access.expression.SecurityExpressionRoot#hasRole(String)}.
	 * For example, if hasRole("ADMIN") or hasRole("ROLE_ADMIN") is passed in, then the
	 * role ROLE_ADMIN will be used when the defaultRolePrefix is "ROLE_" (default).
	 * @param defaultRolePrefix the default prefix to add to roles. The default is
	 * "ROLE_".
	 * @since 5.8
	 * @deprecated Use
	 * {@link #setAuthorizationManagerFactory(AuthorizationManagerFactory)} instead
	 */
	@Deprecated(since = "7.0")
	public void setDefaultRolePrefix(String defaultRolePrefix) {
		getDefaultAuthorizationManagerFactory().setRolePrefix(defaultRolePrefix);
		this.defaultRolePrefix = defaultRolePrefix;
	}

}
