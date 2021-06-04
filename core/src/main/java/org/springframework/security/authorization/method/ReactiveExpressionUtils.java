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

import reactor.core.publisher.Mono;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.EvaluationException;
import org.springframework.expression.Expression;

/**
 * For internal use only, as this contract is likely to change.
 *
 * @author Evgeniy Cheban
 * @since 5.8
 */
final class ReactiveExpressionUtils {

	static Mono<Boolean> evaluateAsBoolean(Expression expr, EvaluationContext ctx) {
		return Mono.defer(() -> {
			Object value;
			try {
				value = expr.getValue(ctx);
			}
			catch (EvaluationException ex) {
				return Mono.error(() -> new IllegalArgumentException(
						"Failed to evaluate expression '" + expr.getExpressionString() + "'", ex));
			}
			if (value instanceof Boolean) {
				return Mono.just((Boolean) value);
			}
			if (value instanceof Mono<?>) {
				Mono<?> monoValue = (Mono<?>) value;
				// @formatter:off
				return monoValue
						.filter(Boolean.class::isInstance)
						.map(Boolean.class::cast)
						.switchIfEmpty(createInvalidReturnTypeMono(expr));
				// @formatter:on
			}
			return createInvalidReturnTypeMono(expr);
		});
	}

	private static Mono<Boolean> createInvalidReturnTypeMono(Expression expr) {
		return Mono.error(() -> new IllegalStateException(
				"Expression: '" + expr.getExpressionString() + "' must return boolean or Mono<Boolean>"));
	}

	private ReactiveExpressionUtils() {
	}

}
