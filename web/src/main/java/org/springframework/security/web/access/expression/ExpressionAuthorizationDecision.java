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

package org.springframework.security.web.access.expression;

import org.springframework.expression.Expression;
import org.springframework.security.authorization.AuthorizationDecision;

/**
 * An expression-based {@link AuthorizationDecision}.
 *
 * @author Evgeniy Cheban
 * @since 5.8
 */
public final class ExpressionAuthorizationDecision extends AuthorizationDecision {

	private final Expression expression;

	/**
	 * Creates an instance.
	 * @param granted the decision to use
	 * @param expression the {@link Expression} to use
	 */
	public ExpressionAuthorizationDecision(boolean granted, Expression expression) {
		super(granted);
		this.expression = expression;
	}

	/**
	 * Returns the {@link Expression}.
	 * @return the {@link Expression} to use
	 */
	public Expression getExpression() {
		return this.expression;
	}

	@Override
	public String toString() {
		return "ExpressionAuthorizationDecision[granted=" + isGranted() + ", expression='" + this.expression + "']";
	}

}
