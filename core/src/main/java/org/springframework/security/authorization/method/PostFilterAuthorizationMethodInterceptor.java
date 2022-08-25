/*
 * Copyright 2002-2022 the original author or authors.
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

import java.util.function.Supplier;

import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;

import org.springframework.aop.Pointcut;
import org.springframework.aop.PointcutAdvisor;
import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.core.Ordered;
import org.springframework.expression.EvaluationContext;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;

/**
 * A {@link MethodInterceptor} which filters a {@code returnedObject} from the
 * {@link MethodInvocation} by evaluating an expression from the {@link PostFilter}
 * annotation.
 *
 * @author Evgeniy Cheban
 * @author Josh Cummings
 * @since 5.6
 */
public final class PostFilterAuthorizationMethodInterceptor
		implements Ordered, MethodInterceptor, PointcutAdvisor, AopInfrastructureBean {

	private Supplier<Authentication> authentication = getAuthentication(
			SecurityContextHolder.getContextHolderStrategy());

	private PostFilterExpressionAttributeRegistry registry = new PostFilterExpressionAttributeRegistry();

	private int order = AuthorizationInterceptorsOrder.POST_FILTER.getOrder();

	private final Pointcut pointcut;

	/**
	 * Creates a {@link PostFilterAuthorizationMethodInterceptor} using the provided
	 * parameters
	 */
	public PostFilterAuthorizationMethodInterceptor() {
		this.pointcut = AuthorizationMethodPointcuts.forAnnotations(PostFilter.class);
	}

	/**
	 * Use this {@link MethodSecurityExpressionHandler}.
	 * @param expressionHandler the {@link MethodSecurityExpressionHandler} to use
	 */
	public void setExpressionHandler(MethodSecurityExpressionHandler expressionHandler) {
		this.registry = new PostFilterExpressionAttributeRegistry(expressionHandler);
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
	 * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
	 * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
	 *
	 * @since 5.8
	 */
	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy strategy) {
		this.authentication = getAuthentication(strategy);
	}

	/**
	 * Filter a {@code returnedObject} using the {@link PostFilter} annotation that the
	 * {@link MethodInvocation} specifies.
	 * @param mi the {@link MethodInvocation} to check check
	 * @return filtered {@code returnedObject}
	 */
	@Override
	public Object invoke(MethodInvocation mi) throws Throwable {
		Object returnedObject = mi.proceed();
		ExpressionAttribute attribute = this.registry.getAttribute(mi);
		if (attribute == ExpressionAttribute.NULL_ATTRIBUTE) {
			return returnedObject;
		}
		MethodSecurityExpressionHandler expressionHandler = this.registry.getExpressionHandler();
		EvaluationContext ctx = expressionHandler.createEvaluationContext(this.authentication, mi);
		return expressionHandler.filter(returnedObject, attribute.getExpression(), ctx);
	}

	private Supplier<Authentication> getAuthentication(SecurityContextHolderStrategy strategy) {
		return () -> {
			Authentication authentication = strategy.getContext().getAuthentication();
			if (authentication == null) {
				throw new AuthenticationCredentialsNotFoundException(
						"An Authentication object was not found in the SecurityContext");
			}
			return authentication;
		};
	}

}
