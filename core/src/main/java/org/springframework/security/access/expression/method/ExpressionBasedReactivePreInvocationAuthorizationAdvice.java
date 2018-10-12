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

import reactor.core.Exceptions;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.aop.ProxyMethodInvocation;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.lang.Nullable;
import org.springframework.security.access.expression.ReactiveExpressionUtils;
import org.springframework.security.access.prepost.PreInvocationAttribute;
import org.springframework.security.access.prepost.ReactivePreInvocationAuthorizationAdvice;
import org.springframework.security.core.Authentication;
import org.springframework.security.util.SimpleMethodInvocation;
import org.springframework.util.StringUtils;

/**
 * Reactive argument filtering and authorization logic based on expressions.
 * <p>
 *   Reactive equivalent of {@link ExpressionBasedPreInvocationAdvice}
 * </p>
 *
 * @author Eric Deandrea
 * @since 5.1.2
 * @see ExpressionBasedPreInvocationAdvice
 */
public class ExpressionBasedReactivePreInvocationAuthorizationAdvice implements ReactivePreInvocationAuthorizationAdvice {
	private final ReactiveMethodSecurityExpressionHandler expressionHandler;

	public ExpressionBasedReactivePreInvocationAuthorizationAdvice() {
		this(null);
	}

	public ExpressionBasedReactivePreInvocationAuthorizationAdvice(@Nullable ReactiveMethodSecurityExpressionHandler expressionHandler) {
		this.expressionHandler = Optional.ofNullable(expressionHandler).orElseGet(DefaultReactiveMethodSecurityExpressionHandler::new);
	}

	@Override
	public Mono<Boolean> before(Authentication authentication, MethodInvocation mi, @Nullable PreInvocationAttribute preInvocationAttribute) {
		Optional<PreInvocationExpressionAttribute> preAttr = Optional.ofNullable(preInvocationAttribute)
				.filter(PreInvocationExpressionAttribute.class::isInstance)
				.map(PreInvocationExpressionAttribute.class::cast);

		EvaluationContext ctx = this.expressionHandler.createEvaluationContext(authentication, mi);

		preAttr
				.map(PreInvocationExpressionAttribute::getFilterExpression)
				.ifPresent(preFilter -> preAttr
						.map(PreInvocationExpressionAttribute::getFilterTarget)
						.ifPresent(filterTargetName -> applyFilterTarget(filterTargetName, preFilter, ctx, mi))
				);

		return preAttr
				.map(PreInvocationExpressionAttribute::getAuthorizeExpression)
				.map(preAuthorize -> ReactiveExpressionUtils.evaluateAsBoolean(preAuthorize, ctx))
				.orElseGet(() -> Mono.defer(() -> Mono.just(true)));
	}

	private <T extends Publisher<?>> void applyFilterTarget(@Nullable String filterTargetName, Expression preFilter, @Nullable EvaluationContext ctx, MethodInvocation mi) {
		if (StringUtils.hasText(filterTargetName)) {
			Optional<EvaluationContext> contextOptional = Optional.ofNullable(ctx);
			T filterTarget = (T) contextOptional
					.map(evaluationContext -> evaluationContext.lookupVariable(filterTargetName))
					.filter(Publisher.class::isInstance)
					.map(Publisher.class::cast)
					.orElseThrow(() -> Exceptions.propagate(
							new IllegalArgumentException(
									String.format(
											"Filter target was null, or no argument with name %s found in method",
											filterTargetName))
							)
					);

			contextOptional
					.filter(MethodSecurityEvaluationContext.class::isInstance)
					.map(MethodSecurityEvaluationContext.class::cast)
					.ifPresent(evaluationContext -> {
						evaluationContext.setVariable(filterTargetName, this.expressionHandler.filter(filterTarget, preFilter, evaluationContext));
						setArguments(mi, evaluationContext.getMethodInvocationArgs());
					});
		}
		else if (mi.getArguments().length == 1) {
			Object arg = mi.getArguments()[0];
			T filterTarget = (T) Optional.ofNullable(arg)
					.filter(Publisher.class::isInstance)
					.map(Publisher.class::cast)
					.orElseThrow(() -> Exceptions.propagate(
							new IllegalArgumentException(
									String.format(
											"A PreFilter expression was set but the method argument type %s is not a %s",
											getErrorClass(arg.getClass()),
											Publisher.class.getName()))
							)
					);

			setArguments(mi, this.expressionHandler.filter(filterTarget, preFilter, ctx));
		}
	}

	private void setArguments(MethodInvocation mi, Object... arguments) {
		// On the non-reactive side the filter will actually mutate the Collection that is passed in
		// during the method invocation (see DefaultMethodSecurityExpressionHandler.filter
		// Here we don't have that luxury - reactive types are immutable, so we need to
		// apply a filter to the Publisher chain
		// Therefore we need a hook into the set of arguments that are actually passed in
		// during the method invocation
		if (ProxyMethodInvocation.class.isInstance(mi)) {
			((ProxyMethodInvocation) mi).setArguments(arguments);
		}
		else if (SimpleMethodInvocation.class.isInstance(mi)) {
			((SimpleMethodInvocation) mi).setArguments(arguments);
		}
	}

	private Class<?> getErrorClass(Class<?> clazz) {
		if (Mono.class.isAssignableFrom(clazz)) {
			return Mono.class;
		}
		else if (Flux.class.isAssignableFrom(clazz)) {
			return Flux.class;
		}
		else if (Publisher.class.isAssignableFrom(clazz)) {
			return Publisher.class;
		}

		return clazz;
	}
}
