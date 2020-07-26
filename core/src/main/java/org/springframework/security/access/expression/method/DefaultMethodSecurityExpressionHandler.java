/*
 * Copyright 2002-2020 the original author or authors.
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
package org.springframework.security.access.expression.method;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.PermissionCacheOptimizer;
import org.springframework.security.access.expression.AbstractSecurityExpressionHandler;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.parameters.DefaultSecurityParameterNameDiscoverer;
import org.springframework.util.Assert;

/**
 * The standard implementation of {@code MethodSecurityExpressionHandler}.
 * <p>
 * A single instance should usually be shared amongst the beans that require expression
 * support.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class DefaultMethodSecurityExpressionHandler extends AbstractSecurityExpressionHandler<MethodInvocation>
		implements MethodSecurityExpressionHandler {

	protected final Log logger = LogFactory.getLog(getClass());

	private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

	private ParameterNameDiscoverer parameterNameDiscoverer = new DefaultSecurityParameterNameDiscoverer();

	private PermissionCacheOptimizer permissionCacheOptimizer = null;

	private String defaultRolePrefix = "ROLE_";

	public DefaultMethodSecurityExpressionHandler() {
	}

	/**
	 * Uses a {@link MethodSecurityEvaluationContext} as the <tt>EvaluationContext</tt>
	 * implementation.
	 */
	@Override
	public StandardEvaluationContext createEvaluationContextInternal(Authentication auth, MethodInvocation mi) {
		return new MethodSecurityEvaluationContext(auth, mi, getParameterNameDiscoverer());
	}

	/**
	 * Creates the root object for expression evaluation.
	 */
	@Override
	protected MethodSecurityExpressionOperations createSecurityExpressionRoot(Authentication authentication,
			MethodInvocation invocation) {
		MethodSecurityExpressionRoot root = new MethodSecurityExpressionRoot(authentication);
		root.setThis(invocation.getThis());
		root.setPermissionEvaluator(getPermissionEvaluator());
		root.setTrustResolver(getTrustResolver());
		root.setRoleHierarchy(getRoleHierarchy());
		root.setDefaultRolePrefix(getDefaultRolePrefix());

		return root;
	}

	/**
	 * Filters the {@code filterTarget} object (which must be either a collection, array,
	 * map or stream), by evaluating the supplied expression.
	 * <p>
	 * If a {@code Collection} or {@code Map} is used, the original instance will be
	 * modified to contain the elements for which the permission expression evaluates to
	 * {@code true}. For an array, a new array instance will be returned.
	 */
	@Override
	@SuppressWarnings("unchecked")
	public Object filter(Object filterTarget, Expression filterExpression, EvaluationContext ctx) {
		MethodSecurityExpressionOperations rootObject = (MethodSecurityExpressionOperations) ctx.getRootObject()
				.getValue();
		final boolean debug = this.logger.isDebugEnabled();
		List retainList;

		if (debug) {
			this.logger.debug("Filtering with expression: " + filterExpression.getExpressionString());
		}

		if (filterTarget instanceof Collection) {
			Collection collection = (Collection) filterTarget;
			retainList = new ArrayList(collection.size());

			if (debug) {
				this.logger.debug("Filtering collection with " + collection.size() + " elements");
			}

			if (this.permissionCacheOptimizer != null) {
				this.permissionCacheOptimizer.cachePermissionsFor(rootObject.getAuthentication(), collection);
			}

			for (Object filterObject : (Collection) filterTarget) {
				rootObject.setFilterObject(filterObject);

				if (ExpressionUtils.evaluateAsBoolean(filterExpression, ctx)) {
					retainList.add(filterObject);
				}
			}

			if (debug) {
				this.logger.debug("Retaining elements: " + retainList);
			}

			collection.clear();
			collection.addAll(retainList);

			return filterTarget;
		}

		if (filterTarget.getClass().isArray()) {
			Object[] array = (Object[]) filterTarget;
			retainList = new ArrayList(array.length);

			if (debug) {
				this.logger.debug("Filtering array with " + array.length + " elements");
			}

			if (this.permissionCacheOptimizer != null) {
				this.permissionCacheOptimizer.cachePermissionsFor(rootObject.getAuthentication(), Arrays.asList(array));
			}

			for (Object o : array) {
				rootObject.setFilterObject(o);

				if (ExpressionUtils.evaluateAsBoolean(filterExpression, ctx)) {
					retainList.add(o);
				}
			}

			if (debug) {
				this.logger.debug("Retaining elements: " + retainList);
			}

			Object[] filtered = (Object[]) Array.newInstance(filterTarget.getClass().getComponentType(),
					retainList.size());
			for (int i = 0; i < retainList.size(); i++) {
				filtered[i] = retainList.get(i);
			}

			return filtered;
		}

		if (filterTarget instanceof Map) {
			final Map<?, ?> map = (Map<?, ?>) filterTarget;
			final Map retainMap = new LinkedHashMap(map.size());

			if (debug) {
				this.logger.debug("Filtering map with " + map.size() + " elements");
			}

			for (Map.Entry<?, ?> filterObject : map.entrySet()) {
				rootObject.setFilterObject(filterObject);

				if (ExpressionUtils.evaluateAsBoolean(filterExpression, ctx)) {
					retainMap.put(filterObject.getKey(), filterObject.getValue());
				}
			}

			if (debug) {
				this.logger.debug("Retaining elements: " + retainMap);
			}

			map.clear();
			map.putAll(retainMap);

			return filterTarget;
		}

		if (filterTarget instanceof Stream) {
			final Stream<?> original = (Stream<?>) filterTarget;

			return original.filter(filterObject -> {
				rootObject.setFilterObject(filterObject);
				return ExpressionUtils.evaluateAsBoolean(filterExpression, ctx);
			}).onClose(original::close);
		}

		throw new IllegalArgumentException(
				"Filter target must be a collection, array, map or stream type, but was " + filterTarget);
	}

	/**
	 * Sets the {@link AuthenticationTrustResolver} to be used. The default is
	 * {@link AuthenticationTrustResolverImpl}.
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
		return this.trustResolver;
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
		return this.parameterNameDiscoverer;
	}

	public void setPermissionCacheOptimizer(PermissionCacheOptimizer permissionCacheOptimizer) {
		this.permissionCacheOptimizer = permissionCacheOptimizer;
	}

	@Override
	public void setReturnObject(Object returnObject, EvaluationContext ctx) {
		((MethodSecurityExpressionOperations) ctx.getRootObject().getValue()).setReturnObject(returnObject);
	}

	/**
	 * <p>
	 * Sets the default prefix to be added to
	 * {@link org.springframework.security.access.expression.SecurityExpressionRoot#hasAnyRole(String...)}
	 * or
	 * {@link org.springframework.security.access.expression.SecurityExpressionRoot#hasRole(String)}.
	 * For example, if hasRole("ADMIN") or hasRole("ROLE_ADMIN") is passed in, then the
	 * role ROLE_ADMIN will be used when the defaultRolePrefix is "ROLE_" (default).
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

	/**
	 * @return The default role prefix
	 */
	protected String getDefaultRolePrefix() {
		return this.defaultRolePrefix;
	}

}
