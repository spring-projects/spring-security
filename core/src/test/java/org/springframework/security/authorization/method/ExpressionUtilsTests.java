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

package org.springframework.security.authorization.method;

import org.junit.jupiter.api.Test;

import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.authorization.ExpressionAuthorizationDecision;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class ExpressionUtilsTests {

	private final Object details = new Object();

	@Test
	public void evaluateWhenAuthorizationDecisionThenReturns() {
		SpelExpressionParser parser = new SpelExpressionParser();
		Expression expression = parser.parseExpression("#root.returnDecision()");
		StandardEvaluationContext context = new StandardEvaluationContext(this);
		assertThat(ExpressionUtils.evaluate(expression, context)).isInstanceOf(AuthorizationDecisionDetails.class)
			.extracting("details")
			.isEqualTo(this.details);
	}

	@Test
	public void evaluateWhenBooleanThenReturnsExpressionAuthorizationDecision() {
		SpelExpressionParser parser = new SpelExpressionParser();
		Expression expression = parser.parseExpression("#root.returnResult()");
		StandardEvaluationContext context = new StandardEvaluationContext(this);
		assertThat(ExpressionUtils.evaluate(expression, context)).isInstanceOf(ExpressionAuthorizationDecision.class);
	}

	@Test
	public void evaluateWhenExpressionThrowsAuthorizationDeniedExceptionThenPropagates() {
		SpelExpressionParser parser = new SpelExpressionParser();
		Expression expression = parser.parseExpression("#root.throwException()");
		StandardEvaluationContext context = new StandardEvaluationContext(this);
		assertThatExceptionOfType(AuthorizationDeniedException.class)
			.isThrownBy(() -> ExpressionUtils.evaluate(expression, context));
	}

	public AuthorizationDecision returnDecision() {
		return new AuthorizationDecisionDetails(false, this.details);
	}

	public Object throwException() {
		throw new AuthorizationDeniedException("denied", new AuthorizationDecision(false));
	}

	public boolean returnResult() {
		return false;
	}

	static final class AuthorizationDecisionDetails extends AuthorizationDecision {

		final Object details;

		AuthorizationDecisionDetails(boolean granted, Object details) {
			super(granted);
			this.details = details;
		}

	}

}
