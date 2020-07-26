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

import java.util.Collection;

import org.springframework.expression.EvaluationContext;
import org.springframework.messaging.Message;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * Voter which handles {@link Message} authorisation decisions. If a
 * {@link MessageExpressionConfigAttribute} is found, then its expression is evaluated. If
 * true, {@code ACCESS_GRANTED} is returned. If false, {@code ACCESS_DENIED} is returned.
 * If no {@code MessageExpressionConfigAttribute} is found, then {@code ACCESS_ABSTAIN} is
 * returned.
 *
 * @author Rob Winch
 * @author Daniel Bustamante Ospina
 * @since 4.0
 */
public class MessageExpressionVoter<T> implements AccessDecisionVoter<Message<T>> {

	private SecurityExpressionHandler<Message<T>> expressionHandler = new DefaultMessageSecurityExpressionHandler<>();

	public int vote(Authentication authentication, Message<T> message, Collection<ConfigAttribute> attributes) {
		assert authentication != null;
		assert message != null;
		assert attributes != null;

		MessageExpressionConfigAttribute attr = findConfigAttribute(attributes);

		if (attr == null) {
			return ACCESS_ABSTAIN;
		}

		EvaluationContext ctx = this.expressionHandler.createEvaluationContext(authentication, message);
		ctx = attr.postProcess(ctx, message);

		return ExpressionUtils.evaluateAsBoolean(attr.getAuthorizeExpression(), ctx) ? ACCESS_GRANTED : ACCESS_DENIED;
	}

	private MessageExpressionConfigAttribute findConfigAttribute(Collection<ConfigAttribute> attributes) {
		for (ConfigAttribute attribute : attributes) {
			if (attribute instanceof MessageExpressionConfigAttribute) {
				return (MessageExpressionConfigAttribute) attribute;
			}
		}
		return null;
	}

	public boolean supports(ConfigAttribute attribute) {
		return attribute instanceof MessageExpressionConfigAttribute;
	}

	public boolean supports(Class<?> clazz) {
		return Message.class.isAssignableFrom(clazz);
	}

	public void setExpressionHandler(SecurityExpressionHandler<Message<T>> expressionHandler) {
		Assert.notNull(expressionHandler, "expressionHandler cannot be null");
		this.expressionHandler = expressionHandler;
	}

}
