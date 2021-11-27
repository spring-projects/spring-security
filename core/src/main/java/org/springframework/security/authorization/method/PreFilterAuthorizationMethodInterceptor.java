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

import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;

import org.springframework.aop.Pointcut;
import org.springframework.aop.PointcutAdvisor;
import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.aop.support.AopUtils;
import org.springframework.core.Ordered;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.lang.NonNull;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * A {@link MethodInterceptor} which filters a method argument by evaluating an expression
 * from the {@link PreFilter} annotation.
 *
 * @author Evgeniy Cheban
 * @author Josh Cummings
 * @since 5.6
 */
public final class PreFilterAuthorizationMethodInterceptor
		implements Ordered, MethodInterceptor, PointcutAdvisor, AopInfrastructureBean {

	private static final Supplier<Authentication> AUTHENTICATION_SUPPLIER = () -> {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null) {
			throw new AuthenticationCredentialsNotFoundException(
					"An Authentication object was not found in the SecurityContext");
		}
		return authentication;
	};

	private final PreFilterExpressionAttributeRegistry registry = new PreFilterExpressionAttributeRegistry();

	private int order = AuthorizationInterceptorsOrder.PRE_FILTER.getOrder();

	private final Pointcut pointcut;

	private MethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();

	/**
	 * Creates a {@link PreFilterAuthorizationMethodInterceptor} using the provided
	 * parameters
	 */
	public PreFilterAuthorizationMethodInterceptor() {
		this.pointcut = AuthorizationMethodPointcuts.forAnnotations(PreFilter.class);
	}

	/**
	 * Use this {@link MethodSecurityExpressionHandler}
	 * @param expressionHandler the {@link MethodSecurityExpressionHandler} to use
	 */
	public void setExpressionHandler(MethodSecurityExpressionHandler expressionHandler) {
		Assert.notNull(expressionHandler, "expressionHandler cannot be null");
		this.expressionHandler = expressionHandler;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int getOrder() {
		return this.order;
	}

	public void setOrder(int order) {
		this.order = order;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Pointcut getPointcut() {
		return this.pointcut;
	}

	@Override
	public Advice getAdvice() {
		return this;
	}

	@Override
	public boolean isPerInstance() {
		return true;
	}

	/**
	 * Filter the method argument specified in the {@link PreFilter} annotation that
	 * {@link MethodInvocation} specifies.
	 * @param mi the {@link MethodInvocation} to check
	 */
	@Override
	public Object invoke(MethodInvocation mi) throws Throwable {
		PreFilterExpressionAttribute attribute = this.registry.getAttribute(mi);
		if (attribute == PreFilterExpressionAttribute.NULL_ATTRIBUTE) {
			return mi.proceed();
		}
		EvaluationContext ctx = this.expressionHandler.createEvaluationContext(AUTHENTICATION_SUPPLIER.get(), mi);
		Object filterTarget = findFilterTarget(attribute.filterTarget, ctx, mi);
		this.expressionHandler.filter(filterTarget, attribute.getExpression(), ctx);
		return mi.proceed();
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
			Expression preFilterExpression = PreFilterAuthorizationMethodInterceptor.this.expressionHandler
					.getExpressionParser().parseExpression(preFilter.value());
			return new PreFilterExpressionAttribute(preFilterExpression, preFilter.filterTarget());
		}

		private PreFilter findPreFilterAnnotation(Method method) {
			PreFilter preFilter = AuthorizationAnnotationUtils.findUniqueAnnotation(method, PreFilter.class);
			return (preFilter != null) ? preFilter
					: AuthorizationAnnotationUtils.findUniqueAnnotation(method.getDeclaringClass(), PreFilter.class);
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
