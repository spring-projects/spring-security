/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.messaging.access.expression;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.messaging.Message;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.core.Authentication;
import org.springframework.security.messaging.util.matcher.MessageMatcher;

import java.util.Arrays;
import java.util.Collection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static org.springframework.security.access.AccessDecisionVoter.*;

@RunWith(MockitoJUnitRunner.class)
public class MessageExpressionVoterTests {
	@Mock
	Authentication authentication;
	@Mock
	Message<Object> message;
	Collection<ConfigAttribute> attributes;
	@Mock
	Expression expression;
	@Mock
	MessageMatcher<?> matcher;
	@Mock
	SecurityExpressionHandler<Message> expressionHandler;
	@Mock
	EvaluationContext evaluationContext;

	MessageExpressionVoter voter;

	@Before
	public void setup() {
		attributes = Arrays
				.<ConfigAttribute> asList(new MessageExpressionConfigAttribute(expression, matcher));

		voter = new MessageExpressionVoter();
	}

	@Test
	public void voteGranted() {
		when(expression.getValue(any(EvaluationContext.class), eq(Boolean.class)))
				.thenReturn(true);
		assertThat(voter.vote(authentication, message, attributes)).isEqualTo(
				ACCESS_GRANTED);
	}

	@Test
	public void voteDenied() {
		when(expression.getValue(any(EvaluationContext.class), eq(Boolean.class)))
				.thenReturn(false);
		assertThat(voter.vote(authentication, message, attributes)).isEqualTo(
				ACCESS_DENIED);
	}

	@Test
	public void voteAbstain() {
		attributes = Arrays.<ConfigAttribute> asList(new SecurityConfig("ROLE_USER"));
		assertThat(voter.vote(authentication, message, attributes)).isEqualTo(
				ACCESS_ABSTAIN);
	}

	@Test
	public void supportsObjectClassFalse() {
		assertThat(voter.supports(Object.class)).isFalse();
	}

	@Test
	public void supportsMessageClassTrue() {
		assertThat(voter.supports(Message.class)).isTrue();
	}

	@Test
	public void supportsSecurityConfigFalse() {
		assertThat(voter.supports(new SecurityConfig("ROLE_USER"))).isFalse();
	}

	@Test
	public void supportsMessageExpressionConfigAttributeTrue() {
		assertThat(voter.supports(new MessageExpressionConfigAttribute(expression, matcher)))
				.isTrue();
	}

	@Test(expected = IllegalArgumentException.class)
	public void setExpressionHandlerNull() {
		voter.setExpressionHandler(null);
	}

	@Test
	public void customExpressionHandler() {
		voter.setExpressionHandler(expressionHandler);
		when(expressionHandler.createEvaluationContext(authentication, message))
				.thenReturn(evaluationContext);
		when(expression.getValue(evaluationContext, Boolean.class)).thenReturn(true);

		assertThat(voter.vote(authentication, message, attributes)).isEqualTo(
				ACCESS_GRANTED);

		verify(expressionHandler).createEvaluationContext(authentication, message);
	}

	@Test
	public void postProcessEvaluationContext(){
		final MessageExpressionConfigAttribute configAttribute = mock(MessageExpressionConfigAttribute.class);
		voter.setExpressionHandler(expressionHandler);
		when(expressionHandler.createEvaluationContext(authentication, message)).thenReturn(evaluationContext);
		when(configAttribute.getAuthorizeExpression()).thenReturn(expression);
		attributes = Arrays.<ConfigAttribute> asList(configAttribute);
		when(configAttribute.postProcess(evaluationContext, message)).thenReturn(evaluationContext);
		when(expression.getValue(any(EvaluationContext.class), eq(Boolean.class)))
				.thenReturn(true);

		assertThat(voter.vote(authentication, message, attributes)).isEqualTo(
				ACCESS_GRANTED);
		verify(configAttribute).postProcess(evaluationContext, message);
	}
}
