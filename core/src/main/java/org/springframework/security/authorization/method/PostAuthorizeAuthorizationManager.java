/*
 * Copyright 2002-2024 the original author or authors.
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

import org.springframework.context.ApplicationContext;
import org.springframework.expression.EvaluationContext;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;

/**
 * An {@link AuthorizationManager} which can determine if an {@link Authentication} may
 * return the result from an invoked {@link MethodInvocation} by evaluating an expression
 * from the {@link PostAuthorize} annotation.
 *
 * @author Evgeniy Cheban
 * @since 5.6
 */
public final class PostAuthorizeAuthorizationManager
		implements AuthorizationManager<MethodInvocationResult>, MethodAuthorizationDeniedHandler {

	private PostAuthorizeExpressionAttributeRegistry registry = new PostAuthorizeExpressionAttributeRegistry();

	/**
	 * Use this the {@link MethodSecurityExpressionHandler}.
	 * @param expressionHandler the {@link MethodSecurityExpressionHandler} to use
	 */
	public void setExpressionHandler(MethodSecurityExpressionHandler expressionHandler) {
		this.registry.setExpressionHandler(expressionHandler);
	}

	/**
	 * Configure pre/post-authorization template resolution
	 * <p>
	 * By default, this value is <code>null</code>, which indicates that templates should
	 * not be resolved.
	 * @param defaults - whether to resolve pre/post-authorization templates parameters
	 * @since 6.3
	 * @deprecated Please use
	 * {@link #setTemplateDefaults(AnnotationTemplateExpressionDefaults)} instead
	 */
	@Deprecated
	public void setTemplateDefaults(PrePostTemplateDefaults defaults) {
		this.registry.setTemplateDefaults(defaults);
	}

	/**
	 * Configure pre/post-authorization template resolution
	 * <p>
	 * By default, this value is <code>null</code>, which indicates that templates should
	 * not be resolved.
	 * @param defaults - whether to resolve pre/post-authorization templates parameters
	 * @since 6.4
	 */
	public void setTemplateDefaults(AnnotationTemplateExpressionDefaults defaults) {
		this.registry.setTemplateDefaults(defaults);
	}

	/**
	 * Invokes
	 * {@link PostAuthorizeExpressionAttributeRegistry#setApplicationContext(ApplicationContext)}
	 * with the provided {@link ApplicationContext}.
	 * @param context the {@link ApplicationContext}
	 * @since 6.3
	 * @see PreAuthorizeExpressionAttributeRegistry#setApplicationContext(ApplicationContext)
	 */
	public void setApplicationContext(ApplicationContext context) {
		this.registry.setApplicationContext(context);
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
		return (AuthorizationDecision) ExpressionUtils.evaluate(attribute.getExpression(), ctx);
	}

	@Override
	public Object handleDeniedInvocation(MethodInvocation methodInvocation, AuthorizationResult authorizationResult) {
		ExpressionAttribute attribute = this.registry.getAttribute(methodInvocation);
		PostAuthorizeExpressionAttribute postAuthorizeAttribute = (PostAuthorizeExpressionAttribute) attribute;
		return postAuthorizeAttribute.getHandler().handleDeniedInvocation(methodInvocation, authorizationResult);
	}

	@Override
	public Object handleDeniedInvocationResult(MethodInvocationResult methodInvocationResult,
			AuthorizationResult authorizationResult) {
		ExpressionAttribute attribute = this.registry.getAttribute(methodInvocationResult.getMethodInvocation());
		PostAuthorizeExpressionAttribute postAuthorizeAttribute = (PostAuthorizeExpressionAttribute) attribute;
		return postAuthorizeAttribute.getHandler()
			.handleDeniedInvocationResult(methodInvocationResult, authorizationResult);
	}

}
