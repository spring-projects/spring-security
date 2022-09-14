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

import org.aopalliance.intercept.MethodInvocation;
import reactor.core.publisher.Mono;

import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * A {@link ReactiveAuthorizationManager} which can determine if an {@link Authentication}
 * has access to the returned object from the {@link MethodInvocation} by evaluating an
 * expression from the {@link PostAuthorize} annotation.
 *
 * @author Evgeniy Cheban
 * @since 5.8
 */
public final class PostAuthorizeReactiveAuthorizationManager
		implements ReactiveAuthorizationManager<MethodInvocationResult> {

	private final PostAuthorizeExpressionAttributeRegistry registry;

	public PostAuthorizeReactiveAuthorizationManager() {
		this(new DefaultMethodSecurityExpressionHandler());
	}

	public PostAuthorizeReactiveAuthorizationManager(MethodSecurityExpressionHandler expressionHandler) {
		Assert.notNull(expressionHandler, "expressionHandler cannot be null");
		this.registry = new PostAuthorizeExpressionAttributeRegistry(expressionHandler);
	}

	/**
	 * Determines if an {@link Authentication} has access to the returned object from the
	 * {@link MethodInvocation} by evaluating an expression from the {@link PostAuthorize}
	 * annotation.
	 * @param authentication the {@link Mono} of the {@link Authentication} to check
	 * @param result the {@link MethodInvocationResult} to check
	 * @return a Mono of the {@link AuthorizationDecision} or an empty {@link Mono} if the
	 * {@link PostAuthorize} annotation is not present
	 */
	@Override
	public Mono<AuthorizationDecision> check(Mono<Authentication> authentication, MethodInvocationResult result) {
		MethodInvocation mi = result.getMethodInvocation();
		ExpressionAttribute attribute = this.registry.getAttribute(mi);
		if (attribute == ExpressionAttribute.NULL_ATTRIBUTE) {
			return Mono.empty();
		}
		MethodSecurityExpressionHandler expressionHandler = this.registry.getExpressionHandler();
		// @formatter:off
		return authentication
				.map((auth) -> expressionHandler.createEvaluationContext(auth, mi))
				.doOnNext((ctx) -> expressionHandler.setReturnObject(result.getResult(), ctx))
				.flatMap((ctx) -> ReactiveExpressionUtils.evaluateAsBoolean(attribute.getExpression(), ctx))
				.map((granted) -> new ExpressionAttributeAuthorizationDecision(granted, attribute));
		// @formatter:on
	}

}
