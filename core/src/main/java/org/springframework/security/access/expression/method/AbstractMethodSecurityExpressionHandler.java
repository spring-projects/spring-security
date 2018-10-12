/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.access.expression.method;

import org.aopalliance.intercept.MethodInvocation;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.PermissionCacheOptimizer;
import org.springframework.security.access.expression.AbstractSecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.parameters.DefaultSecurityParameterNameDiscoverer;
import org.springframework.util.Assert;

/**
 * Base class for method security expression handlers
 *
 * @author Eric Deandrea
 * @since 5.1.2
 */
public abstract class AbstractMethodSecurityExpressionHandler extends AbstractSecurityExpressionHandler<MethodInvocation> {
	protected final Log logger = LogFactory.getLog(getClass());

	private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
	private ParameterNameDiscoverer parameterNameDiscoverer = new DefaultSecurityParameterNameDiscoverer();
	private PermissionCacheOptimizer permissionCacheOptimizer = null;
	private String defaultRolePrefix = "ROLE_";

	/**
	 * Uses a {@link MethodSecurityEvaluationContext} as the <tt>EvaluationContext</tt>
	 * implementation.
	 */
	@Override
	public StandardEvaluationContext createEvaluationContextInternal(Authentication auth,
			MethodInvocation mi) {
		return new MethodSecurityEvaluationContext(auth, mi, getParameterNameDiscoverer());
	}

	/**
	 * Creates the root object for expression evaluation.
	 */
	@Override
	protected MethodSecurityExpressionOperations createSecurityExpressionRoot(
			Authentication authentication, MethodInvocation invocation) {
		MethodSecurityExpressionRoot root = new MethodSecurityExpressionRoot(
				authentication);
		root.setThis(invocation.getThis());
		root.setPermissionEvaluator(getPermissionEvaluator());
		root.setTrustResolver(getTrustResolver());
		root.setRoleHierarchy(getRoleHierarchy());
		root.setDefaultRolePrefix(getDefaultRolePrefix());

		return root;
	}

	/**
	 * Sets the {@link AuthenticationTrustResolver} to be used. The default is
	 * {@link AuthenticationTrustResolverImpl}.
	 *
	 * @param trustResolver the {@link AuthenticationTrustResolver} to use. Cannot be
	 * null.
	 */
	public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
		Assert.notNull(trustResolver, "trustResolver cannot be null");
		this.trustResolver = trustResolver;
	}

	/**
	 * @return The current {@link AuthenticationTrustResolver}
	 */
	protected AuthenticationTrustResolver getTrustResolver() {
		return trustResolver;
	}

	/**
	 * Sets the {@link ParameterNameDiscoverer} to use. The default is
	 * {@link DefaultSecurityParameterNameDiscoverer}.
	 * @param parameterNameDiscoverer
	 */
	public void setParameterNameDiscoverer(ParameterNameDiscoverer parameterNameDiscoverer) {
		this.parameterNameDiscoverer = parameterNameDiscoverer;
	}

	/**
	 * @return The current {@link ParameterNameDiscoverer}
	 */
	protected ParameterNameDiscoverer getParameterNameDiscoverer() {
		return parameterNameDiscoverer;
	}

	public void setPermissionCacheOptimizer(PermissionCacheOptimizer permissionCacheOptimizer) {
		this.permissionCacheOptimizer = permissionCacheOptimizer;
	}

	protected PermissionCacheOptimizer getPermissionCacheOptimizer() {
		return this.permissionCacheOptimizer;
	}

	public void setReturnObject(Object returnObject, EvaluationContext ctx) {
		((MethodSecurityExpressionOperations) ctx.getRootObject().getValue())
				.setReturnObject(returnObject);
	}

	/**
	 * <p>
	 * Sets the default prefix to be added to {@link org.springframework.security.access.expression.SecurityExpressionRoot#hasAnyRole(String...)} or
	 * {@link org.springframework.security.access.expression.SecurityExpressionRoot#hasRole(String)}. For example, if hasRole("ADMIN") or hasRole("ROLE_ADMIN")
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

	/**
	 * @return The default role prefix
	 */
	protected String getDefaultRolePrefix() {
		return defaultRolePrefix;
	}
}
