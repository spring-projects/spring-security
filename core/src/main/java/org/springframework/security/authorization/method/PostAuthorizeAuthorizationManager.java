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
import reactor.util.annotation.NonNull;

import org.springframework.aop.support.AopUtils;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * An {@link AuthorizationManager} which can determine if an {@link Authentication} may
 * return the result from an invoked {@link MethodInvocation} by evaluating an expression
 * from the {@link PostAuthorize} annotation.
 *
 * @author Evgeniy Cheban
 * @since 5.6
 */
public final class PostAuthorizeAuthorizationManager implements AuthorizationManager<MethodInvocationResult> {

	private final PostAuthorizeExpressionAttributeRegistry registry = new PostAuthorizeExpressionAttributeRegistry();

	private MethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();

	/**
	 * Use this the {@link MethodSecurityExpressionHandler}.
	 * @param expressionHandler the {@link MethodSecurityExpressionHandler} to use
	 */
	public void setExpressionHandler(MethodSecurityExpressionHandler expressionHandler) {
		Assert.notNull(expressionHandler, "expressionHandler cannot be null");
		this.expressionHandler = expressionHandler;
	}

	/**
	 * Determine if an {@link Authentication} has access to the returned object by
	 * evaluating the {@link PostAuthorize} annotation that the {@link MethodInvocation}
	 * specifies.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param mi the {@link MethodInvocationResult} to check
	 * @return an {@link AuthorizationDecision} or {@code null} if the
	 * {@link PostAuthorize} annotation is not present
	 */
	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, MethodInvocationResult mi) {
		ExpressionAttribute attribute = this.registry.getAttribute(mi.getMethodInvocation());
		if (attribute == ExpressionAttribute.NULL_ATTRIBUTE) {
			return null;
		}
		EvaluationContext ctx = this.expressionHandler.createEvaluationContext(authentication.get(),
				mi.getMethodInvocation());
		this.expressionHandler.setReturnObject(mi.getResult(), ctx);
		boolean granted = ExpressionUtils.evaluateAsBoolean(attribute.getExpression(), ctx);
		return new AuthorizationDecision(granted);
	}

	private final class PostAuthorizeExpressionAttributeRegistry
			extends AbstractExpressionAttributeRegistry<ExpressionAttribute> {

		@NonNull
		@Override
		ExpressionAttribute resolveAttribute(Method method, Class<?> targetClass) {
			Method specificMethod = AopUtils.getMostSpecificMethod(method, targetClass);
			PostAuthorize postAuthorize = findPostAuthorizeAnnotation(specificMethod);
			if (postAuthorize == null) {
				return ExpressionAttribute.NULL_ATTRIBUTE;
			}
			Expression postAuthorizeExpression = PostAuthorizeAuthorizationManager.this.expressionHandler
					.getExpressionParser().parseExpression(postAuthorize.value());
			return new ExpressionAttribute(postAuthorizeExpression);
		}

		private PostAuthorize findPostAuthorizeAnnotation(Method method) {
			PostAuthorize postAuthorize = AuthorizationAnnotationUtils.findUniqueAnnotation(method,
					PostAuthorize.class);
			return (postAuthorize != null) ? postAuthorize : AuthorizationAnnotationUtils
					.findUniqueAnnotation(method.getDeclaringClass(), PostAuthorize.class);
		}

	}

}
