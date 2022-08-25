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
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * A {@link ReactiveAuthorizationManager} which can determine if an {@link Authentication}
 * has access to the {@link MethodInvocation} by evaluating an expression from the
 * {@link PreAuthorize} annotation.
 *
 * @author Evgeniy Cheban
 * @since 5.8
 */
public final class PreAuthorizeReactiveAuthorizationManager implements ReactiveAuthorizationManager<MethodInvocation> {

	private final PreAuthorizeExpressionAttributeRegistry registry;

	public PreAuthorizeReactiveAuthorizationManager() {
		this(new DefaultMethodSecurityExpressionHandler());
	}

	public PreAuthorizeReactiveAuthorizationManager(MethodSecurityExpressionHandler expressionHandler) {
		Assert.notNull(expressionHandler, "expressionHandler cannot be null");
		this.registry = new PreAuthorizeExpressionAttributeRegistry(expressionHandler);
	}

	/**
	 * Determines if an {@link Authentication} has access to the {@link MethodInvocation}
	 * by evaluating an expression from the {@link PreAuthorize} annotation.
	 * @param authentication the {@link Mono} of the {@link Authentication} to check
	 * @param mi the {@link MethodInvocation} to check
	 * @return a {@link Mono} of the {@link AuthorizationDecision} or an empty
	 * {@link Mono} if the {@link PreAuthorize} annotation is not present
	 */
	@Override
	public Mono<AuthorizationDecision> check(Mono<Authentication> authentication, MethodInvocation mi) {
		ExpressionAttribute attribute = this.registry.getAttribute(mi);
		if (attribute == ExpressionAttribute.NULL_ATTRIBUTE) {
			return Mono.empty();
		}
		// @formatter:off
		return authentication
				.map((auth) -> this.registry.getExpressionHandler().createEvaluationContext(auth, mi))
				.flatMap((ctx) -> ReactiveExpressionUtils.evaluateAsBoolean(attribute.getExpression(), ctx))
				.map((granted) -> new ExpressionAttributeAuthorizationDecision(granted, attribute));
		// @formatter:on
	}

}
