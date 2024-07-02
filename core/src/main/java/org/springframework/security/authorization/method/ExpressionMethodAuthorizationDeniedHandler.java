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

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.util.Assert;

/**
 * {@link MethodAuthorizationDeniedHandler} implementation, that return authorization
 * result, based on SpEL expression.
 *
 * @author Max Batischev
 * @since 6.3
 */
final class ExpressionMethodAuthorizationDeniedHandler implements MethodAuthorizationDeniedHandler {

	private final String expression;

	private final ExpressionParser expressionParser;

	ExpressionMethodAuthorizationDeniedHandler(String expression, ExpressionParser expressionParser) {
		Assert.notNull(expressionParser, "expressionParser cannot be null");
		Assert.notNull(expression, "expression cannot be null");
		this.expressionParser = expressionParser;
		this.expression = expression;
	}

	@Override
	public Object handleDeniedInvocation(MethodInvocation methodInvocation, AuthorizationResult authorizationResult) {
		Expression expression = this.expressionParser.parseExpression(this.expression);
		return expression.getValue();
	}

}
