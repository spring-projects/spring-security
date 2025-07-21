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

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.messaging.Message;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.messaging.util.matcher.MessageMatcher;
import org.springframework.util.Assert;

/**
 * Simple expression configuration attribute for use in {@link Message} authorizations.
 *
 * @author Rob Winch
 * @author Daniel Bustamante Ospina
 * @since 4.0
 * @deprecated Use
 * {@link org.springframework.security.messaging.access.intercept.MessageMatcherDelegatingAuthorizationManager}
 * instead
 */
@Deprecated
@SuppressWarnings("serial")
class MessageExpressionConfigAttribute implements ConfigAttribute, EvaluationContextPostProcessor<Message<?>> {

	private final Expression authorizeExpression;

	private final MessageMatcher<Object> matcher;

	/**
	 * Creates a new instance
	 * @param authorizeExpression the {@link Expression} to use. Cannot be null
	 * @param matcher the {@link MessageMatcher} used to match the messages.
	 */
	MessageExpressionConfigAttribute(Expression authorizeExpression, MessageMatcher<?> matcher) {
		Assert.notNull(authorizeExpression, "authorizeExpression cannot be null");
		Assert.notNull(matcher, "matcher cannot be null");
		this.authorizeExpression = authorizeExpression;
		this.matcher = (MessageMatcher<Object>) matcher;
	}

	Expression getAuthorizeExpression() {
		return this.authorizeExpression;
	}

	@Override
	public String getAttribute() {
		return null;
	}

	@Override
	public String toString() {
		return this.authorizeExpression.getExpressionString();
	}

	@Override
	public EvaluationContext postProcess(EvaluationContext ctx, Message<?> message) {
		Map<String, String> variables = this.matcher.matcher(message).getVariables();
		for (Map.Entry<String, String> entry : variables.entrySet()) {
			ctx.setVariable(entry.getKey(), entry.getValue());
		}
		return ctx;
	}

}
