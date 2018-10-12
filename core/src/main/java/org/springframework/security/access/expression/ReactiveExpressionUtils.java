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
package org.springframework.security.access.expression;

import reactor.core.publisher.Mono;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.EvaluationException;
import org.springframework.expression.Expression;

/**
 * Reactive version of {@link ExpressionUtils} for evaluating expressions that return reactive types.
 *
 * @author Eric Deandrea
 * @since 5.1.2
 */
public final class ReactiveExpressionUtils {
	/**
	 * Evaluates an {@link Expression} that can either return a {@code boolean} or a {@code Mono<Boolean>}.
	 * @param expr The {@link Expression}
	 * @param ctx The {@link EvaluationContext}
	 * @return A {@link Mono} that can be subscribed to containing the result of the expression
	 */
	public static Mono<Boolean> evaluateAsBoolean(Expression expr, EvaluationContext ctx) {
		return Mono.defer(() -> {
			try {
				Object value = expr.getValue(ctx);

				if (value instanceof Boolean) {
					return Mono.just((Boolean) value);
				}
				else if (value instanceof Mono) {
					return ((Mono<?>) value)
							.filter(Boolean.class::isInstance)
							.cast(Boolean.class)
							.switchIfEmpty(createInvalidTypeMono(expr));
				}
				else {
					return createInvalidTypeMono(expr);
				}
			}
			catch (EvaluationException ex) {
				return Mono.error(new IllegalArgumentException(String.format("Failed to evaluate expression '%s': %s", expr.getExpressionString(), ex.getMessage()), ex));
			}
		});
	}

	private static Mono<Boolean> createInvalidTypeMono(Expression expr) {
		return Mono.error(new IllegalArgumentException(String.format("Expression '%s' needs to either return boolean or Mono<Boolean> but it does not", expr.getExpressionString())));
	}
}
