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
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * Base implementation of the facade which isolates Spring Security's requirements for
 * evaluating security expressions from the implementation of the underlying expression
 * objects.
 *
 * @author Luke Taylor
 * @since 3.1
 */
public abstract class AbstractSecurityExpressionHandler<T> implements
		SecurityExpressionHandler<T>, ApplicationContextAware {
	private ExpressionParser expressionParser = new SpelExpressionParser();
	private BeanResolver br;
	private ApplicationContext context;
	private RoleHierarchy roleHierarchy;
	private PermissionEvaluator permissionEvaluator = new DenyAllPermissionEvaluator();
	private boolean roleHierarchySet = false;
	private boolean permissionEvaluatorSet = false;


	public final ExpressionParser getExpressionParser() {
		return expressionParser;
	}

	public final void setExpressionParser(ExpressionParser expressionParser) {
		Assert.notNull(expressionParser, "expressionParser cannot be null");
		this.expressionParser = expressionParser;
	}

	/**
	 * Invokes the internal template methods to create {@code StandardEvaluationContext}
	 * and {@code SecurityExpressionRoot} objects.
	 *
	 * @param authentication the current authentication object
	 * @param invocation the invocation (filter, method, channel)
	 * @return the context object for use in evaluating the expression, populated with a
	 * suitable root object.
	 */
	public final EvaluationContext createEvaluationContext(Authentication authentication,
			T invocation) {
		SecurityExpressionOperations root = createSecurityExpressionRoot(authentication,
				invocation);
		StandardEvaluationContext ctx = createEvaluationContextInternal(authentication,
				invocation);
		ctx.setBeanResolver(br);
		ctx.setRootObject(root);

		return ctx;
	}

	/**
	 * Override to create a custom instance of {@code StandardEvaluationContext}.
	 * <p>
	 * The returned object will have a {@code SecurityExpressionRootPropertyAccessor}
	 * added, allowing beans in the {@code ApplicationContext} to be accessed via
	 * expression properties.
	 *
	 * @param authentication the current authentication object
	 * @param invocation the invocation (filter, method, channel)
	 * @return A {@code StandardEvaluationContext} or potentially a custom subclass if
	 * overridden.
	 */
	protected StandardEvaluationContext createEvaluationContextInternal(
			Authentication authentication, T invocation) {
		return new StandardEvaluationContext();
	}

	/**
	 * Implement in order to create a root object of the correct type for the supported
	 * invocation type.
	 *
	 * @param authentication the current authentication object
	 * @param invocation the invocation (filter, method, channel)
	 * @return the object wh
	 */
	protected abstract SecurityExpressionOperations createSecurityExpressionRoot(
			Authentication authentication, T invocation);

	private boolean roleHerarchyNotSetForValidContext() {
		return ! roleHierarchySet && context != null;
	}

	protected RoleHierarchy getRoleHierarchy() {
		if(roleHerarchyNotSetForValidContext()) {
			RoleHierarchy contextRoleHierarchy = getSingleBeanOrNull(RoleHierarchy.class);
			if(contextRoleHierarchy != null){
				roleHierarchy = contextRoleHierarchy;
			}
			roleHierarchySet = true;
		}
		return roleHierarchy;
	}

	public void setRoleHierarchy(RoleHierarchy roleHierarchy) {
		roleHierarchySet = true;
		this.roleHierarchy = roleHierarchy;
	}

	protected PermissionEvaluator getPermissionEvaluator() {
		if(! permissionEvaluatorSet && context != null) {
			PermissionEvaluator contextPermissionEvaluator = getSingleBeanOrNull(PermissionEvaluator.class);
			if(contextPermissionEvaluator != null){
				permissionEvaluator = contextPermissionEvaluator;
			}
			permissionEvaluatorSet = true;
		}
		return permissionEvaluator;
	}

	public void setPermissionEvaluator(PermissionEvaluator permissionEvaluator) {
		permissionEvaluatorSet = true;
		this.permissionEvaluator = permissionEvaluator;
	}

	public void setApplicationContext(ApplicationContext applicationContext) {
		br = new BeanFactoryResolver(applicationContext);
		this.context = applicationContext;
	}

	private <T> T getSingleBeanOrNull(Class<T> type) {
		String[] beanNamesForType = context.getBeanNamesForType(type);
		if (beanNamesForType == null || beanNamesForType.length != 1) {
			return null;
		}
		return context.getBean(beanNamesForType[0], type);
	}
}
