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

package org.springframework.security.messaging.access.expression;

import java.util.function.Supplier;

import org.jspecify.annotations.Nullable;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.ExpressionAuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.messaging.access.intercept.MessageAuthorizationContext;
import org.springframework.util.Assert;

/**
 * An expression-based {@link AuthorizationManager} that determines the access by
 * evaluating the provided expression.
 *
 * @since 7.1
 */
public final class MessageExpressionAuthorizationManager
		implements AuthorizationManager<MessageAuthorizationContext<?>> {

	private final SecurityExpressionHandler<MessageAuthorizationContext<?>> expressionHandler;

	private final Expression expression;

	/**
	 * Creates an instance.
	 * @param expressionString the raw expression string to parse
	 */
	public MessageExpressionAuthorizationManager(String expressionString) {
		this(new MessageAuthorizationContextSecurityExpressionHandler(), expressionString);
	}

	private MessageExpressionAuthorizationManager(
			SecurityExpressionHandler<MessageAuthorizationContext<?>> expressionHandler, String expressionString) {
		Assert.notNull(expressionHandler, "expressionHandler cannot be null");
		Assert.hasText(expressionString, "expressionString cannot be empty");
		this.expressionHandler = expressionHandler;
		this.expression = expressionHandler.getExpressionParser().parseExpression(expressionString);
	}

	/**
	 * Use a {@link MessageAuthorizationContextSecurityExpressionHandler} to create
	 * {@link MessageExpressionAuthorizationManager} instances.
	 * @return a {@link Builder} for constructing
	 * {@link MessageExpressionAuthorizationManager} instances
	 * @since 7.1
	 */
	public static Builder withDefaults() {
		return new Builder(new MessageAuthorizationContextSecurityExpressionHandler());
	}

	/**
	 * Use this {@link SecurityExpressionHandler} to create
	 * {@link MessageExpressionAuthorizationManager} instances.
	 * @param expressionHandler the expression handler to use
	 * @return a {@link Builder} for constructing
	 * {@link MessageExpressionAuthorizationManager} instances
	 * @since 7.1
	 */
	public static Builder withSecurityExpressionHandler(
			SecurityExpressionHandler<MessageAuthorizationContext<?>> expressionHandler) {
		Assert.notNull(expressionHandler, "expressionHandler cannot be null");
		return new Builder(expressionHandler);
	}

	/**
	 * Determines the access by evaluating the provided expression.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param context the {@link MessageAuthorizationContext} to check
	 * @return an {@link ExpressionAuthorizationDecision} based on the evaluated
	 * expression
	 */
	@Override
	public AuthorizationResult authorize(Supplier<? extends @Nullable Authentication> authentication,
			MessageAuthorizationContext<?> context) {
		EvaluationContext ctx = this.expressionHandler.createEvaluationContext(authentication, context);
		boolean granted = ExpressionUtils.evaluateAsBoolean(this.expression, ctx);
		return new ExpressionAuthorizationDecision(granted, this.expression);
	}

	@Override
	public String toString() {
		return "MessageExpressionAuthorizationManager[expression='" + this.expression + "']";
	}

	/**
	 * A {@link Builder} for constructing {@link MessageExpressionAuthorizationManager}
	 * instances.
	 *
	 * <p>
	 * May be reused to create multiple instances.
	 *
	 * @since 7.1
	 */
	public static final class Builder {

		private final SecurityExpressionHandler<MessageAuthorizationContext<?>> expressionHandler;

		private Builder(SecurityExpressionHandler<MessageAuthorizationContext<?>> expressionHandler) {
			this.expressionHandler = expressionHandler;
		}

		/**
		 * Create a {@link MessageExpressionAuthorizationManager} using this
		 * {@code expression}.
		 * @param expression the expression to evaluate
		 * @return the resulting {@link AuthorizationManager}
		 */
		public MessageExpressionAuthorizationManager expression(String expression) {
			return new MessageExpressionAuthorizationManager(this.expressionHandler, expression);
		}

	}

}
