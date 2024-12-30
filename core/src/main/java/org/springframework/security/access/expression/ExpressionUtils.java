/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.access.expression;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.EvaluationException;
import org.springframework.expression.Expression;

public final class ExpressionUtils {

	private ExpressionUtils() {
	}

	public static boolean evaluateAsBoolean(Expression expr, EvaluationContext ctx) {
		try {
			return expr.getValue(ctx, Boolean.class);
		}
		catch (EvaluationException ex) {
			throw new IllegalArgumentException("Failed to evaluate expression '" + expr.getExpressionString() + "'",
					ex);
		}
	}

}
