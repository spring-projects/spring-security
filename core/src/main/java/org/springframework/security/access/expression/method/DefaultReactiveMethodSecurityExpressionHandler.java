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
import java.util.function.Function;

import org.reactivestreams.Publisher;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.lang.Nullable;
import org.springframework.security.access.PermissionCacheOptimizer;
import org.springframework.security.access.expression.ReactiveExpressionUtils;

/**
 * The standard implementation of {@link ReactiveMethodSecurityExpressionHandler}.
 * <p>
 *   A single instance should usually be shared amongst the beans that require expression
 *   support.
 * </p>
 * <p>
 *   This is the reactive equivalent of {@link DefaultMethodSecurityExpressionHandler}.
 * </p>
 *
 * @author Eric Deandrea
 * @since 5.1.2
 * @see DefaultMethodSecurityExpressionHandler
 */
public class DefaultReactiveMethodSecurityExpressionHandler extends AbstractMethodSecurityExpressionHandler
		implements ReactiveMethodSecurityExpressionHandler {

	@Override
	public <T extends Publisher<?>> T filter(T filterTarget, @Nullable Expression filterExpression, EvaluationContext ctx) {
		return Optional.ofNullable(filterExpression)
				.map(filter -> applyFilter(filterTarget, filter, ctx))
				.orElse(filterTarget);
	}

	private <T extends Publisher<?>> T applyFilter(T filterTarget, Expression filterExpression, EvaluationContext ctx) {
		MethodSecurityExpressionOperations rootObject = (MethodSecurityExpressionOperations) ctx
				.getRootObject().getValue();

		Class<?> returnType = filterTarget.getClass();

		Function<Object, ? extends Publisher<Boolean>> filter = item -> {
			rootObject.setFilterObject(item);
			return ReactiveExpressionUtils.evaluateAsBoolean(filterExpression, ctx);
		};

		if (Mono.class.isAssignableFrom(returnType)) {
			return (T) ((Mono<?>) filterTarget)
					.filterWhen(filter);
		}
		else if (Flux.class.isAssignableFrom(returnType)) {
			return (T) ((Flux<?>) filterTarget)
					.filterWhen(filter);
		}

		return (T) Flux.from(filterTarget)
				.filterWhen(filter);
	}

	/**
	 * Sets the {@link PermissionCacheOptimizer}. Currently just throws {@link UnsupportedOperationException}.
	 * <p>
	 *   This is currently not yet supported on the reactive stack
	 * </p>
	 * @param permissionCacheOptimizer The {@link PermissionCacheOptimizer} to set
	 */
	@Override
	public void setPermissionCacheOptimizer(PermissionCacheOptimizer permissionCacheOptimizer) {
		throw new UnsupportedOperationException("PermissionCacheOptimizer is not yet supported on the reactive stack!");
	}
}
