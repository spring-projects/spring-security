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

package org.springframework.security.messaging.access.expression;

import java.util.Map;
import java.util.function.Supplier;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.messaging.Message;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.core.Authentication;
import org.springframework.security.messaging.access.intercept.MessageAuthorizationContext;

/**
 * An expression handler for {@link MessageAuthorizationContext}.
 *
 * @author Josh Cummings
 * @since 5.8
 */
public final class MessageAuthorizationContextSecurityExpressionHandler
		implements SecurityExpressionHandler<MessageAuthorizationContext<?>> {

	private final SecurityExpressionHandler<Message<?>> delegate;

	@SuppressWarnings("rawtypes")
	public MessageAuthorizationContextSecurityExpressionHandler() {
		this(new DefaultMessageSecurityExpressionHandler());
	}

	public MessageAuthorizationContextSecurityExpressionHandler(
			SecurityExpressionHandler<Message<?>> expressionHandler) {
		this.delegate = expressionHandler;
	}

	@Override
	public ExpressionParser getExpressionParser() {
		return this.delegate.getExpressionParser();
	}

	@Override
	public EvaluationContext createEvaluationContext(Authentication authentication,
			MessageAuthorizationContext<?> message) {
		return createEvaluationContext(() -> authentication, message);
	}

	@Override
	public EvaluationContext createEvaluationContext(Supplier<Authentication> authentication,
			MessageAuthorizationContext<?> message) {
		EvaluationContext context = this.delegate.createEvaluationContext(authentication, message.getMessage());
		Map<String, String> variables = message.getVariables();
		if (variables != null) {
			for (Map.Entry<String, String> entry : variables.entrySet()) {
				context.setVariable(entry.getKey(), entry.getValue());
			}
		}
		return context;
	}

}
