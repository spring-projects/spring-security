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

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.aop.support.AopUtils;
import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.parameters.DefaultSecurityParameterNameDiscoverer;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * A {@link MethodInterceptor} which filters a reactive method argument by evaluating an
 * expression from the {@link PreFilter} annotation.
 *
 * @author Evgeniy Cheban
 */
public final class PreFilterAuthorizationBeforeReactiveMethodInterceptor extends AbstractReactiveMethodInterceptor {

	private final PreFilterExpressionAttributeRegistry registry = new PreFilterExpressionAttributeRegistry();

	private final ParameterNameDiscoverer parameterNameDiscoverer = new DefaultSecurityParameterNameDiscoverer();

	/**
	 * Creates an instance.
	 */
	public PreFilterAuthorizationBeforeReactiveMethodInterceptor() {
		super(AuthorizationMethodPointcuts.forAnnotations(PreFilter.class));
	}

	/**
	 * Sets the {@link MethodSecurityExpressionHandler}.
	 * @param expressionHandler the {@link MethodSecurityExpressionHandler} to use
	 */
	public void setExpressionHandler(MethodSecurityExpressionHandler expressionHandler) {
		this.registry.setExpressionHandler(expressionHandler);
	}

	/**
	 * Filters the reactive method argument by evaluating an expression from the
	 * {@link PreFilter} annotation.
	 * @param authentication the {@link Mono} of the {@link Authentication} to check
	 * @param mi the {@link MethodInvocation} to check
	 * @return a {@link Mono} of the {@link Authentication} to use
	 */
	@Override
	protected Mono<?> before(Mono<Authentication> authentication, MethodInvocation mi) {
		PreFilterExpressionAttributeRegistry.PreFilterExpressionAttribute attribute = this.registry.getAttribute(mi);
		if (attribute == PreFilterExpressionAttributeRegistry.PreFilterExpressionAttribute.NULL_ATTRIBUTE) {
			return Mono.empty();
		}
		MethodSecurityExpressionHandler expressionHandler = this.registry.getExpressionHandler();
		Mono<EvaluationContext> toInvoke = authentication
				.map((auth) -> expressionHandler.createEvaluationContext(auth, mi));
		FilterTarget filterTarget = findFilterTarget(attribute.getFilterTarget(), mi);
		if (filterTarget.value instanceof Mono<?>) {
			mi.getArguments()[filterTarget.index] = toInvoke
					.flatMap((ctx) -> filterMono((Mono<?>) filterTarget.value, attribute.getExpression(), ctx));
		}
		else if (filterTarget.value instanceof Flux<?>) {
			mi.getArguments()[filterTarget.index] = toInvoke
					.flatMapMany((ctx) -> filterFlux((Flux<?>) filterTarget.value, attribute.getExpression(), ctx));
		}
		return authentication;
	}

	private FilterTarget findFilterTarget(String name, MethodInvocation mi) {
		Object value = null;
		int index = 0;
		if (StringUtils.hasText(name)) {
			Object target = mi.getThis();
			Class<?> targetClass = (target != null) ? AopUtils.getTargetClass(target) : null;
			Method specificMethod = AopUtils.getMostSpecificMethod(mi.getMethod(), targetClass);
			String[] parameterNames = this.parameterNameDiscoverer.getParameterNames(specificMethod);
			if (parameterNames != null && parameterNames.length > 0) {
				Object[] arguments = mi.getArguments();
				for (index = 0; index < parameterNames.length; index++) {
					if (name.equals(parameterNames[index])) {
						value = arguments[index];
						break;
					}
				}
				Assert.notNull(value,
						"Filter target was null, or no argument with name '" + name + "' found in method.");
			}
		}
		else {
			Object[] arguments = mi.getArguments();
			Assert.state(arguments.length == 1,
					"Unable to determine the method argument for filtering. Specify the filter target.");
			value = arguments[0];
			Assert.notNull(value,
					"Filter target was null. Make sure you passing the correct value in the method argument.");
		}
		Assert.state(value instanceof Mono<?> || value instanceof Flux<?>,
				"Filter target must be an instance of Mono or Flux.");
		return new FilterTarget(value, index);
	}

	private Flux<?> filterFlux(Flux<?> filterTarget, Expression filterExpression, EvaluationContext ctx) {
		MethodSecurityExpressionOperations rootObject = (MethodSecurityExpressionOperations) ctx.getRootObject()
				.getValue();
		return filterTarget.filterWhen((filterObject) -> {
			rootObject.setFilterObject(filterObject);
			return ReactiveExpressionUtils.evaluateAsBoolean(filterExpression, ctx);
		});
	}

	private Mono<?> filterMono(Mono<?> filterTarget, Expression filterExpression, EvaluationContext ctx) {
		MethodSecurityExpressionOperations rootObject = (MethodSecurityExpressionOperations) ctx.getRootObject()
				.getValue();
		return filterTarget.filterWhen((filterObject) -> {
			rootObject.setFilterObject(filterObject);
			return ReactiveExpressionUtils.evaluateAsBoolean(filterExpression, ctx);
		});
	}

	private static final class FilterTarget {

		private final Object value;

		private final int index;

		private FilterTarget(Object value, int index) {
			this.value = value;
			this.index = index;
		}

	}

}
