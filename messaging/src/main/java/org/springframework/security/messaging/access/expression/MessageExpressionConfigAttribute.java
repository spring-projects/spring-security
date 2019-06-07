/*
 * Copyright 2002-2019 the original author or authors.
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

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.messaging.Message;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.messaging.util.matcher.MessageMatcher;
import org.springframework.security.messaging.util.matcher.SimpDestinationMessageMatcher;
import org.springframework.util.Assert;

import java.util.Map;

/**
 * Simple expression configuration attribute for use in {@link Message} authorizations.
 *
 * @since 4.0
 * @author Rob Winch
 * @author Daniel Bustamante Ospina
 */
@SuppressWarnings("serial")
class MessageExpressionConfigAttribute implements ConfigAttribute, EvaluationContextPostProcessor<Message<?>> {
	private final Expression authorizeExpression;
	private final MessageMatcher<?> matcher;


	/**
	 * Creates a new instance
	 *
	 * @param authorizeExpression the {@link Expression} to use. Cannot be null
	 * @param matcher the {@link MessageMatcher} used to match the messages.
	 */
	public MessageExpressionConfigAttribute(Expression authorizeExpression, MessageMatcher<?> matcher) {
		Assert.notNull(authorizeExpression, "authorizeExpression cannot be null");
		Assert.notNull(matcher, "matcher cannot be null");
		this.authorizeExpression = authorizeExpression;
		this.matcher = matcher;
	}


	Expression getAuthorizeExpression() {
		return authorizeExpression;
	}

	public String getAttribute() {
		return null;
	}

	@Override
	public String toString() {
		return authorizeExpression.getExpressionString();
	}

	@Override
	public EvaluationContext postProcess(EvaluationContext ctx, Message<?> message) {
		if (matcher instanceof SimpDestinationMessageMatcher) {
			final Map<String, String> variables = ((SimpDestinationMessageMatcher) matcher).extractPathVariables(message);
			for (Map.Entry<String, String> entry : variables.entrySet()){
				ctx.setVariable(entry.getKey(), entry.getValue());
			}
		}
		return ctx;
	}
}
