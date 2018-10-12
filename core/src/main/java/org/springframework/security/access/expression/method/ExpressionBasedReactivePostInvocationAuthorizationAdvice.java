/*
 * Copyright 2002-2018 the original author or authors.
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

import java.util.Optional;

import org.aopalliance.intercept.MethodInvocation;
import org.reactivestreams.Publisher;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.expression.EvaluationContext;
import org.springframework.lang.Nullable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.expression.ReactiveExpressionUtils;
import org.springframework.security.access.prepost.PostInvocationAttribute;
import org.springframework.security.access.prepost.ReactivePostInvocationAuthorizationAdvice;
import org.springframework.security.core.Authentication;

/**
 * Reactive argument filtering and authorization logic based on expressions.
 * <p>
 *   Reactive equivalent of {@link ExpressionBasedPostInvocationAdvice}
 * </p>
 *
 * @author Eric Deandrea
 * @since 5.1.2
 * @see ExpressionBasedPostInvocationAdvice
 */
public class ExpressionBasedReactivePostInvocationAuthorizationAdvice implements ReactivePostInvocationAuthorizationAdvice {
	private final ReactiveMethodSecurityExpressionHandler expressionHandler;

	public ExpressionBasedReactivePostInvocationAuthorizationAdvice() {
		this(null);
	}

	public ExpressionBasedReactivePostInvocationAuthorizationAdvice(@Nullable ReactiveMethodSecurityExpressionHandler expressionHandler) {
		this.expressionHandler = Optional.ofNullable(expressionHandler).orElseGet(DefaultReactiveMethodSecurityExpressionHandler::new);
	}

	@Override
	public <T extends Publisher<?>> T after(Authentication authentication, MethodInvocation mi, @Nullable PostInvocationAttribute postInvocationAttribute, T returnedObject) {
		Optional<PostInvocationExpressionAttribute> postAttr = Optional.ofNullable(postInvocationAttribute)
				.filter(PostInvocationExpressionAttribute.class::isInstance)
				.map(PostInvocationExpressionAttribute.class::cast);

		EvaluationContext ctx = this.expressionHandler.createEvaluationContext(authentication, mi);

		T filteredReturnObject = postAttr
				.map(PostInvocationExpressionAttribute::getFilterExpression)
				.map(postFilter -> this.expressionHandler.filter(returnedObject, postFilter, ctx))
				.orElse(returnedObject);

		this.expressionHandler.setReturnObject(filteredReturnObject, ctx);

		Class<?> returnType = filteredReturnObject.getClass();
		Mono<Boolean> authorized = postAttr
				.map(PostInvocationExpressionAttribute::getAuthorizeExpression)
				.map(pa -> ReactiveExpressionUtils.evaluateAsBoolean(pa, ctx))
				.orElseGet(() -> Mono.just(true));

		if (Mono.class.isAssignableFrom(returnType)) {
			return (T) authorized
					.flatMap(isAuthorized -> isAuthorized ? (Mono<?>) filteredReturnObject : Mono.error(this::createAccessDeniedException));
		}
		else if (Flux.class.isAssignableFrom(returnType)) {
			return (T) authorized
					.flatMapMany(isAuthorized -> isAuthorized ? (Flux<?>) filteredReturnObject : Flux.error(this::createAccessDeniedException));
		}

		return (T) authorized
				.flatMapMany(isAuthorized -> isAuthorized ? Flux.from(filteredReturnObject) : Flux.error(this::createAccessDeniedException));
	}

	private AccessDeniedException createAccessDeniedException() {
		return new AccessDeniedException("Access is denied");
	}
}
