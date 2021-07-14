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

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import reactor.core.publisher.Mono;

import org.springframework.expression.EvaluationContext;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.core.Authentication;

/**
 * A {@link MethodInterceptor} which filters the returned object from the
 * {@link MethodInvocation} by evaluating an expression from the {@link PostFilter}
 * annotation.
 *
 * @author Evgeniy Cheban
 */
public final class PostFilterAuthorizationAfterReactiveMethodInterceptor extends AbstractReactiveMethodInterceptor {

	private final PostFilterExpressionAttributeRegistry registry = new PostFilterExpressionAttributeRegistry();

	/**
	 * Creates an instance.
	 */
	public PostFilterAuthorizationAfterReactiveMethodInterceptor() {
		super(AuthorizationMethodPointcuts.forAnnotations(PostFilter.class));
	}

	/**
	 * Sets the {@link MethodSecurityExpressionHandler}.
	 * @param expressionHandler the {@link MethodSecurityExpressionHandler} to use
	 */
	public void setExpressionHandler(MethodSecurityExpressionHandler expressionHandler) {
		this.registry.setExpressionHandler(expressionHandler);
	}

	/**
	 * Filters the returned object from the {@link MethodInvocation} by evaluating an
	 * expression from the {@link PostFilter} annotation.
	 * @param authentication the {@link Mono} of the {@link Authentication} to check
	 * @param result the {@link MethodInvocationResult} to check
	 * @return the {@link Mono} of the {@link MethodInvocationResult#getResult()} if
	 * access is granted or a {@link Mono} error if access is denied
	 */
	@Override
	protected Mono<?> after(Mono<Authentication> authentication, MethodInvocationResult result) {
		MethodInvocation mi = result.getMethodInvocation();
		ExpressionAttribute attribute = this.registry.getAttribute(mi);
		if (attribute == ExpressionAttribute.NULL_ATTRIBUTE) {
			return Mono.just(result.getResult());
		}
		// @formatter:off
		return authentication
				.map((auth) -> this.registry.getExpressionHandler().createEvaluationContext(auth, mi))
				.doOnNext((ctx) -> setFilterObject(ctx, result))
				.flatMap((ctx) -> postFilter(ctx, result, attribute));
		// @formatter:on
	}

	private void setFilterObject(EvaluationContext ctx, MethodInvocationResult result) {
		((MethodSecurityExpressionOperations) ctx.getRootObject().getValue()).setFilterObject(result.getResult());
	}

	private Mono<?> postFilter(EvaluationContext ctx, MethodInvocationResult result, ExpressionAttribute attribute) {
		return ReactiveExpressionUtils.evaluateAsBoolean(attribute.getExpression(), ctx)
				.flatMap((granted) -> granted ? Mono.just(result.getResult()) : Mono.empty());
	}

}
