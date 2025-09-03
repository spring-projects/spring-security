/*
 * Copyright 2004-present the original author or authors.
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

import org.jspecify.annotations.Nullable;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.EvaluationException;
import org.springframework.expression.Expression;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.ExpressionAuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

final class ExpressionUtils {

	private ExpressionUtils() {
	}

	static @Nullable AuthorizationResult evaluate(Expression expr, EvaluationContext ctx) {
		return evaluate(expr, ctx, () -> null, null);
	}

	static <T> @Nullable AuthorizationResult evaluate(Expression expr, EvaluationContext ctx,
			Supplier<? extends @Nullable Authentication> authentication, @Nullable T context) {
		try {
			Object result = expr.getValue(ctx);
			if (result instanceof AuthorizationManager<?> manager) {
				Assert.notNull(authentication, "authentication supplier cannot be null");
				Assert.notNull(context, "context cannot be null");
				return ((AuthorizationManager<T>) manager).authorize(authentication, context);
			}
			if (result instanceof AuthorizationResult decision) {
				return decision;
			}
			if (result instanceof Boolean granted) {
				return new ExpressionAuthorizationDecision(granted, expr);
			}
			if (result == null) {
				return null;
			}
			throw new IllegalArgumentException(
					"SpEL expression must return either a Boolean or an AuthorizationDecision");
		}
		catch (EvaluationException ex) {
			AuthorizationDeniedException denied = findAuthorizationException(ex);
			if (denied != null) {
				throw denied;
			}
			throw new IllegalArgumentException("Failed to evaluate expression '" + expr.getExpressionString() + "'",
					ex);
		}
	}

	static @Nullable AuthorizationDeniedException findAuthorizationException(EvaluationException ex) {
		Throwable cause = ex.getCause();
		while (cause != null) {
			if (cause instanceof AuthorizationDeniedException denied) {
				return denied;
			}
			cause = cause.getCause();
		}
		return null;
	}

}
