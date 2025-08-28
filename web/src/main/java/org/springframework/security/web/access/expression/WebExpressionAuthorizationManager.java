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

package org.springframework.security.web.access.expression;

import java.util.function.Supplier;

import org.jspecify.annotations.Nullable;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.ExpressionAuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.util.Assert;

/**
 * An expression-based {@link AuthorizationManager} that determines the access by
 * evaluating the provided expression.
 *
 * @author Evgeniy Cheban
 * @since 5.8
 */
public final class WebExpressionAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

	private SecurityExpressionHandler<RequestAuthorizationContext> expressionHandler = new DefaultHttpSecurityExpressionHandler();

	private Expression expression;

	/**
	 * Creates an instance.
	 * @param expressionString the raw expression string to parse
	 */
	public WebExpressionAuthorizationManager(String expressionString) {
		Assert.hasText(expressionString, "expressionString cannot be empty");
		this.expression = this.expressionHandler.getExpressionParser().parseExpression(expressionString);
	}

	private WebExpressionAuthorizationManager(String expressionString,
			SecurityExpressionHandler<RequestAuthorizationContext> expressionHandler) {
		Assert.hasText(expressionString, "expressionString cannot be empty");
		this.expressionHandler = expressionHandler;
		this.expression = expressionHandler.getExpressionParser().parseExpression(expressionString);
	}

	/**
	 * Sets the {@link SecurityExpressionHandler} to be used. The default is
	 * {@link DefaultHttpSecurityExpressionHandler}.
	 * @param expressionHandler the {@link SecurityExpressionHandler} to use
	 * @deprecated Please use {@link #withDefaults()} or {@link #withExpressionHandler}
	 */
	@Deprecated
	public void setExpressionHandler(SecurityExpressionHandler<RequestAuthorizationContext> expressionHandler) {
		Assert.notNull(expressionHandler, "expressionHandler cannot be null");
		this.expressionHandler = expressionHandler;
		this.expression = expressionHandler.getExpressionParser()
			.parseExpression(this.expression.getExpressionString());
	}

	/**
	 * Determines the access by evaluating the provided expression.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param context the {@link RequestAuthorizationContext} to check
	 * @return an {@link ExpressionAuthorizationDecision} based on the evaluated
	 * expression
	 */
	@Override
	public AuthorizationResult authorize(Supplier<? extends @Nullable Authentication> authentication,
			RequestAuthorizationContext context) {
		EvaluationContext ctx = this.expressionHandler.createEvaluationContext(authentication, context);
		boolean granted = ExpressionUtils.evaluateAsBoolean(this.expression, ctx);
		return new ExpressionAuthorizationDecision(granted, this.expression);
	}

	@Override
	public String toString() {
		return "WebExpressionAuthorizationManager[expression='" + this.expression + "']";
	}

	/**
	 * Use a {@link DefaultHttpSecurityExpressionHandler} to create
	 * {@link WebExpressionAuthorizationManager} instances.
	 *
	 * <p>
	 * Note that publishing the {@link Builder} as a bean will allow the default
	 * expression handler to be configured with a bean provider so that expressions can
	 * reference beans
	 * @return a {@link Builder} for constructing
	 * {@link WebExpressionAuthorizationManager} instances
	 * @since 7.0
	 */
	public static Builder withDefaults() {
		return new Builder();
	}

	/**
	 * Use this {@link SecurityExpressionHandler} to create
	 * {@link WebExpressionAuthorizationManager} instances
	 * @param expressionHandler
	 * @return a {@link Builder} for constructing
	 * {@link WebExpressionAuthorizationManager} instances
	 * @since 7.0
	 */
	public static Builder withExpressionHandler(
			SecurityExpressionHandler<RequestAuthorizationContext> expressionHandler) {
		return new Builder(expressionHandler);
	}

	/**
	 * A {@link Builder} for constructing {@link WebExpressionAuthorizationManager}
	 * instances.
	 *
	 * <p>
	 * May be reused to create multiple instances.
	 *
	 * @author Josh Cummings
	 * @since 7.0
	 */
	public static final class Builder implements ApplicationContextAware {

		private final SecurityExpressionHandler<RequestAuthorizationContext> expressionHandler;

		private final boolean defaultExpressionHandler;

		private Builder() {
			this.expressionHandler = new DefaultHttpSecurityExpressionHandler();
			this.defaultExpressionHandler = true;
		}

		private Builder(SecurityExpressionHandler<RequestAuthorizationContext> expressionHandler) {
			this.expressionHandler = expressionHandler;
			this.defaultExpressionHandler = false;
		}

		/**
		 * Create a {@link WebExpressionAuthorizationManager} using this
		 * {@code expression}
		 * @param expression the expression to evaluate
		 * @return the resulting {@link AuthorizationManager}
		 */
		public WebExpressionAuthorizationManager expression(String expression) {
			return new WebExpressionAuthorizationManager(expression, this.expressionHandler);
		}

		@Override
		public void setApplicationContext(ApplicationContext context) throws BeansException {
			if (this.defaultExpressionHandler) {
				((DefaultHttpSecurityExpressionHandler) this.expressionHandler).setApplicationContext(context);
			}
		}

	}

}
