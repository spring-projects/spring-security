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

import org.jspecify.annotations.Nullable;

import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.expression.BeanFactoryResolver;
import org.springframework.expression.BeanResolver;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * Base implementation of the facade which isolates Spring Security's requirements for
 * evaluating security expressions from the implementation of the underlying expression
 * objects.
 *
 * @author Luke Taylor
 * @author Evgeniy Cheban
 * @since 3.1
 */
public abstract class AbstractSecurityExpressionHandler<T>
		implements SecurityExpressionHandler<T>, ApplicationContextAware {

	private ExpressionParser expressionParser = new SpelExpressionParser();

	private @Nullable BeanResolver beanResolver;

	private final DefaultAuthorizationManagerFactory<T> defaultAuthorizationManagerFactory = new DefaultAuthorizationManagerFactory<>();

	private AuthorizationManagerFactory<T> authorizationManagerFactory = defaultAuthorizationManagerFactory;

	private PermissionEvaluator permissionEvaluator = new DenyAllPermissionEvaluator();

	@Override
	public final ExpressionParser getExpressionParser() {
		return this.expressionParser;
	}

	public final void setExpressionParser(ExpressionParser expressionParser) {
		Assert.notNull(expressionParser, "expressionParser cannot be null");
		this.expressionParser = expressionParser;
	}

	/**
	 * Invokes the internal template methods to create {@code StandardEvaluationContext}
	 * and {@code SecurityExpressionRoot} objects.
	 * @param authentication the current authentication object
	 * @param invocation the invocation (filter, method, channel)
	 * @return the context object for use in evaluating the expression, populated with a
	 * suitable root object.
	 */
	@Override
	public final EvaluationContext createEvaluationContext(Authentication authentication, T invocation) {
		SecurityExpressionOperations root = createSecurityExpressionRoot(authentication, invocation);
		StandardEvaluationContext ctx = createEvaluationContextInternal(authentication, invocation);
		if (this.beanResolver != null) {
			ctx.setBeanResolver(this.beanResolver);
		}
		ctx.setRootObject(root);
		return ctx;
	}

	/**
	 * Override to create a custom instance of {@code StandardEvaluationContext}.
	 * <p>
	 * The returned object will have a {@code SecurityExpressionRootPropertyAccessor}
	 * added, allowing beans in the {@code ApplicationContext} to be accessed via
	 * expression properties.
	 * @param authentication the current authentication object
	 * @param invocation the invocation (filter, method, channel)
	 * @return A {@code StandardEvaluationContext} or potentially a custom subclass if
	 * overridden.
	 */
	protected StandardEvaluationContext createEvaluationContextInternal(Authentication authentication, T invocation) {
		return new StandardEvaluationContext();
	}

	/**
	 * Implement in order to create a root object of the correct type for the supported
	 * invocation type.
	 * @param authentication the current authentication object
	 * @param invocation the invocation (filter, method, channel)
	 * @return the object
	 */
	protected abstract SecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication,
			T invocation);

	/**
	 * Sets the {@link AuthorizationManagerFactory} to be used. The default is
	 * {@link DefaultAuthorizationManagerFactory}.
	 * @param authorizationManagerFactory the {@link AuthorizationManagerFactory} to use.
	 * Cannot be null.
	 * @since 7.0
	 */
	public final void setAuthorizationManagerFactory(AuthorizationManagerFactory<T> authorizationManagerFactory) {
		Assert.notNull(authorizationManagerFactory, "authorizationManagerFactory cannot be null");
		this.authorizationManagerFactory = authorizationManagerFactory;
	}

	protected final AuthorizationManagerFactory<T> getAuthorizationManagerFactory() {
		return this.authorizationManagerFactory;
	}

	protected final DefaultAuthorizationManagerFactory<T> getDefaultAuthorizationManagerFactory() {
		return this.defaultAuthorizationManagerFactory;
	}

	/**
	 * @deprecated Use {@link #getDefaultAuthorizationManagerFactory()} instead
	 */
	@Deprecated(since = "7.0")
	protected @Nullable RoleHierarchy getRoleHierarchy() {
		return this.defaultAuthorizationManagerFactory.getRoleHierarchy();
	}

	/**
	 * @deprecated Use
	 * {@link #setAuthorizationManagerFactory(AuthorizationManagerFactory)} instead
	 */
	@Deprecated(since = "7.0")
	public void setRoleHierarchy(@Nullable RoleHierarchy roleHierarchy) {
		if (roleHierarchy != null) {
			this.defaultAuthorizationManagerFactory.setRoleHierarchy(roleHierarchy);
		}
	}

	protected PermissionEvaluator getPermissionEvaluator() {
		return this.permissionEvaluator;
	}

	public void setPermissionEvaluator(PermissionEvaluator permissionEvaluator) {
		this.permissionEvaluator = permissionEvaluator;
	}

	protected @Nullable BeanResolver getBeanResolver() {
		return this.beanResolver;
	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) {
		this.beanResolver = new BeanFactoryResolver(applicationContext);
	}

}
