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

import java.util.Arrays;
import java.util.Collection;

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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.security.access.AccessDecisionVoter.ACCESS_ABSTAIN;
import static org.springframework.security.access.AccessDecisionVoter.ACCESS_DENIED;
import static org.springframework.security.access.AccessDecisionVoter.ACCESS_GRANTED;

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
		this.attributes = Arrays
				.<ConfigAttribute>asList(new MessageExpressionConfigAttribute(this.expression, this.matcher));

		this.voter = new MessageExpressionVoter();
	}

	@Test
	public void voteGranted() {
		given(this.expression.getValue(any(EvaluationContext.class), eq(Boolean.class))).willReturn(true);
		assertThat(this.voter.vote(this.authentication, this.message, this.attributes)).isEqualTo(ACCESS_GRANTED);
	}

	@Test
	public void voteDenied() {
		given(this.expression.getValue(any(EvaluationContext.class), eq(Boolean.class))).willReturn(false);
		assertThat(this.voter.vote(this.authentication, this.message, this.attributes)).isEqualTo(ACCESS_DENIED);
	}

	@Test
	public void voteAbstain() {
		this.attributes = Arrays.<ConfigAttribute>asList(new SecurityConfig("ROLE_USER"));
		assertThat(this.voter.vote(this.authentication, this.message, this.attributes)).isEqualTo(ACCESS_ABSTAIN);
	}

	@Test
	public void supportsObjectClassFalse() {
		assertThat(this.voter.supports(Object.class)).isFalse();
	}

	@Test
	public void supportsMessageClassTrue() {
		assertThat(this.voter.supports(Message.class)).isTrue();
	}

	@Test
	public void supportsSecurityConfigFalse() {
		assertThat(this.voter.supports(new SecurityConfig("ROLE_USER"))).isFalse();
	}

	@Test
	public void supportsMessageExpressionConfigAttributeTrue() {
		assertThat(this.voter.supports(new MessageExpressionConfigAttribute(this.expression, this.matcher))).isTrue();
	}

	@Test(expected = IllegalArgumentException.class)
	public void setExpressionHandlerNull() {
		this.voter.setExpressionHandler(null);
	}

	@Test
	public void customExpressionHandler() {
		this.voter.setExpressionHandler(this.expressionHandler);
		given(this.expressionHandler.createEvaluationContext(this.authentication, this.message))
				.willReturn(this.evaluationContext);
		given(this.expression.getValue(this.evaluationContext, Boolean.class)).willReturn(true);

		assertThat(this.voter.vote(this.authentication, this.message, this.attributes)).isEqualTo(ACCESS_GRANTED);

		verify(this.expressionHandler).createEvaluationContext(this.authentication, this.message);
	}

	@Test
	public void postProcessEvaluationContext() {
		final MessageExpressionConfigAttribute configAttribute = mock(MessageExpressionConfigAttribute.class);
		this.voter.setExpressionHandler(this.expressionHandler);
		given(this.expressionHandler.createEvaluationContext(this.authentication, this.message))
				.willReturn(this.evaluationContext);
		given(configAttribute.getAuthorizeExpression()).willReturn(this.expression);
		this.attributes = Arrays.<ConfigAttribute>asList(configAttribute);
		given(configAttribute.postProcess(this.evaluationContext, this.message)).willReturn(this.evaluationContext);
		given(this.expression.getValue(any(EvaluationContext.class), eq(Boolean.class))).willReturn(true);

		assertThat(this.voter.vote(this.authentication, this.message, this.attributes)).isEqualTo(ACCESS_GRANTED);
		verify(configAttribute).postProcess(this.evaluationContext, this.message);
	}

}
