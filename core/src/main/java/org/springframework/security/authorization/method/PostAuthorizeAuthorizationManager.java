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

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.expression.EvaluationContext;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.ExpressionAuthorizationDecision;
import org.springframework.security.core.Authentication;

/**
 * An {@link AuthorizationManager} which can determine if an {@link Authentication} may
 * return the result from an invoked {@link MethodInvocation} by evaluating an expression
 * from the {@link PostAuthorize} annotation.
 *
 * @author Evgeniy Cheban
 * @since 5.6
 */
public final class PostAuthorizeAuthorizationManager implements AuthorizationManager<MethodInvocationResult> {

	private PostAuthorizeExpressionAttributeRegistry registry = new PostAuthorizeExpressionAttributeRegistry();

	/**
	 * Use this the {@link MethodSecurityExpressionHandler}.
	 * @param expressionHandler the {@link MethodSecurityExpressionHandler} to use
	 */
	public void setExpressionHandler(MethodSecurityExpressionHandler expressionHandler) {
		this.registry = new PostAuthorizeExpressionAttributeRegistry(expressionHandler);
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
		MethodSecurityExpressionHandler expressionHandler = this.registry.getExpressionHandler();
		EvaluationContext ctx = expressionHandler.createEvaluationContext(authentication, mi.getMethodInvocation());
		expressionHandler.setReturnObject(mi.getResult(), ctx);
		boolean granted = ExpressionUtils.evaluateAsBoolean(attribute.getExpression(), ctx);
		return new ExpressionAuthorizationDecision(granted, attribute.getExpression());
	}

}
