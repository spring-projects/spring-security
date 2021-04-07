/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.authorization.method;

import java.lang.reflect.Method;
import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.aop.MethodMatcher;
import org.springframework.aop.support.AopUtils;
import org.springframework.aop.support.StaticMethodMatcher;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.lang.NonNull;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * An {@link AuthorizationMethodBeforeAdvice} which filters a method argument by
 * evaluating an expression from the {@link PreFilter} annotation.
 *
 * @author Evgeniy Cheban
 * @since 5.5
 */
public final class PreFilterAuthorizationMethodBeforeAdvice
		implements AuthorizationMethodBeforeAdvice<MethodAuthorizationContext> {

	private final PreFilterExpressionAttributeRegistry registry = new PreFilterExpressionAttributeRegistry();

	private final MethodMatcher methodMatcher = new StaticMethodMatcher() {
		@Override
		public boolean matches(Method method, Class<?> targetClass) {
			return PreFilterAuthorizationMethodBeforeAdvice.this.registry.getAttribute(method,
					targetClass) != PreFilterExpressionAttribute.NULL_ATTRIBUTE;
		}
	};

	private MethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();

	/**
	 * Sets the {@link MethodSecurityExpressionHandler}.
	 * @param expressionHandler the {@link MethodSecurityExpressionHandler} to use
	 */
	public void setExpressionHandler(MethodSecurityExpressionHandler expressionHandler) {
		Assert.notNull(expressionHandler, "expressionHandler cannot be null");
		this.expressionHandler = expressionHandler;
	}

	@Override
	public MethodMatcher getMethodMatcher() {
		return this.methodMatcher;
	}

	/**
	 * Filters a method argument by evaluating an expression from the {@link PreFilter}
	 * annotation.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param methodAuthorizationContext the {@link MethodAuthorizationContext} to check
	 */
	@Override
	public void before(Supplier<Authentication> authentication, MethodAuthorizationContext methodAuthorizationContext) {
		PreFilterExpressionAttribute attribute = this.registry.getAttribute(methodAuthorizationContext);
		if (attribute == PreFilterExpressionAttribute.NULL_ATTRIBUTE) {
			return;
		}
		MethodInvocation mi = methodAuthorizationContext.getMethodInvocation();
		EvaluationContext ctx = this.expressionHandler.createEvaluationContext(authentication.get(), mi);
		Object filterTarget = findFilterTarget(attribute.filterTarget, ctx, mi);
		this.expressionHandler.filter(filterTarget, attribute.getExpression(), ctx);
	}

	private Object findFilterTarget(String filterTargetName, EvaluationContext ctx, MethodInvocation methodInvocation) {
		Object filterTarget;
		if (StringUtils.hasText(filterTargetName)) {
			filterTarget = ctx.lookupVariable(filterTargetName);
			Assert.notNull(filterTarget, () -> "Filter target was null, or no argument with name '" + filterTargetName
					+ "' found in method.");
		}
		else {
			Object[] arguments = methodInvocation.getArguments();
			Assert.state(arguments.length == 1,
					"Unable to determine the method argument for filtering. Specify the filter target.");
			filterTarget = arguments[0];
			Assert.notNull(filterTarget,
					"Filter target was null. Make sure you passing the correct value in the method argument.");
		}
		Assert.state(!filterTarget.getClass().isArray(),
				"Pre-filtering on array types is not supported. Using a Collection will solve this problem.");
		return filterTarget;
	}

	private final class PreFilterExpressionAttributeRegistry
			extends AbstractExpressionAttributeRegistry<PreFilterExpressionAttribute> {

		@NonNull
		@Override
		PreFilterExpressionAttribute resolveAttribute(Method method, Class<?> targetClass) {
			Method specificMethod = AopUtils.getMostSpecificMethod(method, targetClass);
			PreFilter preFilter = findPreFilterAnnotation(specificMethod);
			if (preFilter == null) {
				return PreFilterExpressionAttribute.NULL_ATTRIBUTE;
			}
			Expression preFilterExpression = PreFilterAuthorizationMethodBeforeAdvice.this.expressionHandler
					.getExpressionParser().parseExpression(preFilter.value());
			return new PreFilterExpressionAttribute(preFilterExpression, preFilter.filterTarget());
		}

		private PreFilter findPreFilterAnnotation(Method method) {
			PreFilter preFilter = AnnotationUtils.findAnnotation(method, PreFilter.class);
			return (preFilter != null) ? preFilter
					: AnnotationUtils.findAnnotation(method.getDeclaringClass(), PreFilter.class);
		}

	}

	private static final class PreFilterExpressionAttribute extends ExpressionAttribute {

		private static final PreFilterExpressionAttribute NULL_ATTRIBUTE = new PreFilterExpressionAttribute(null, null);

		private final String filterTarget;

		private PreFilterExpressionAttribute(Expression expression, String filterTarget) {
			super(expression);
			this.filterTarget = filterTarget;
		}

	}

}
