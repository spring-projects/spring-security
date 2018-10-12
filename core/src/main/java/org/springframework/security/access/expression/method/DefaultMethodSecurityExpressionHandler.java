/*
 * Copyright 2002-2016 the original author or authors.
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

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.expression.ExpressionUtils;

/**
 * The standard implementation of {@code MethodSecurityExpressionHandler}.
 * <p>
 * A single instance should usually be shared amongst the beans that require expression
 * support.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class DefaultMethodSecurityExpressionHandler extends AbstractMethodSecurityExpressionHandler
		implements MethodSecurityExpressionHandler {

	protected final Log logger = LogFactory.getLog(getClass());

	/**
	 * Filters the {@code filterTarget} object (which must be either a collection or an
	 * array), by evaluating the supplied expression.
	 * <p>
	 * If a {@code Collection} is used, the original instance will be modified to contain
	 * the elements for which the permission expression evaluates to {@code true}. For an
	 * array, a new array instance will be returned.
	 */
	@Override
	@SuppressWarnings("unchecked")
	public Object filter(Object filterTarget, Expression filterExpression,
			EvaluationContext ctx) {
		MethodSecurityExpressionOperations rootObject = (MethodSecurityExpressionOperations) ctx
				.getRootObject().getValue();
		final boolean debug = logger.isDebugEnabled();
		List retainList;

		if (debug) {
			logger.debug("Filtering with expression: "
					+ filterExpression.getExpressionString());
		}

		if (filterTarget instanceof Collection) {
			Collection collection = (Collection) filterTarget;
			retainList = new ArrayList(collection.size());

			if (debug) {
				logger.debug("Filtering collection with " + collection.size()
						+ " elements");
			}

			Optional.ofNullable(getPermissionCacheOptimizer())
					.ifPresent(permissionCacheOptimizer ->
							permissionCacheOptimizer.cachePermissionsFor(rootObject.getAuthentication(),
									collection)
					);

			for (Object filterObject : (Collection) filterTarget) {
				rootObject.setFilterObject(filterObject);

				if (ExpressionUtils.evaluateAsBoolean(filterExpression, ctx)) {
					retainList.add(filterObject);
				}
			}

			if (debug) {
				logger.debug("Retaining elements: " + retainList);
			}

			collection.clear();
			collection.addAll(retainList);

			return filterTarget;
		}

		if (filterTarget.getClass().isArray()) {
			Object[] array = (Object[]) filterTarget;
			retainList = new ArrayList(array.length);

			if (debug) {
				logger.debug("Filtering array with " + array.length + " elements");
			}

			Optional.ofNullable(getPermissionCacheOptimizer())
					.ifPresent(permissionCacheOptimizer ->
							permissionCacheOptimizer.cachePermissionsFor(rootObject.getAuthentication(),
									Arrays.asList(array))
					);

			for (Object o : array) {
				rootObject.setFilterObject(o);

				if (ExpressionUtils.evaluateAsBoolean(filterExpression, ctx)) {
					retainList.add(o);
				}
			}

			if (debug) {
				logger.debug("Retaining elements: " + retainList);
			}

			Object[] filtered = (Object[]) Array.newInstance(filterTarget.getClass()
					.getComponentType(), retainList.size());
			for (int i = 0; i < retainList.size(); i++) {
				filtered[i] = retainList.get(i);
			}

			return filtered;
		}

		throw new IllegalArgumentException(
				"Filter target must be a collection or array type, but was "
						+ filterTarget);
	}
}
