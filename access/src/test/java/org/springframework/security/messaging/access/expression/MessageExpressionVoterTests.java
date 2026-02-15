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

import java.util.Arrays;
import java.util.Collection;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.messaging.Message;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.core.Authentication;
import org.springframework.security.messaging.util.matcher.MessageMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("deprecation")
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

	@BeforeEach
	public void setup() {
		this.attributes = Arrays
			.<ConfigAttribute>asList(new MessageExpressionConfigAttribute(this.expression, this.matcher));
		this.voter = new MessageExpressionVoter();
	}

	@Test
	@SuppressWarnings("unchecked")
	public void voteGranted() {
		given(this.expression.getValue(any(EvaluationContext.class), eq(Boolean.class))).willReturn(true);
		given(this.matcher.matcher(any())).willCallRealMethod();
		assertThat(this.voter.vote(this.authentication, this.message, this.attributes))
			.isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void voteDenied() {
		given(this.expression.getValue(any(EvaluationContext.class), eq(Boolean.class))).willReturn(false);
		given(this.matcher.matcher(any())).willCallRealMethod();
		assertThat(this.voter.vote(this.authentication, this.message, this.attributes))
			.isEqualTo(AccessDecisionVoter.ACCESS_DENIED);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void voteAbstain() {
		this.attributes = Arrays.<ConfigAttribute>asList(new SecurityConfig("ROLE_USER"));
		assertThat(this.voter.vote(this.authentication, this.message, this.attributes))
			.isEqualTo(AccessDecisionVoter.ACCESS_ABSTAIN);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void supportsObjectClassFalse() {
		assertThat(this.voter.supports(Object.class)).isFalse();
	}

	@Test
	@SuppressWarnings("unchecked")
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

	@Test
	@SuppressWarnings("unchecked")
	public void setExpressionHandlerNull() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.voter.setExpressionHandler(null));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void customExpressionHandler() {
		this.voter.setExpressionHandler(this.expressionHandler);
		given(this.expressionHandler.createEvaluationContext(this.authentication, this.message))
			.willReturn(this.evaluationContext);
		given(this.expression.getValue(this.evaluationContext, Boolean.class)).willReturn(true);
		given(this.matcher.matcher(any())).willCallRealMethod();
		assertThat(this.voter.vote(this.authentication, this.message, this.attributes))
			.isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
		verify(this.expressionHandler).createEvaluationContext(this.authentication, this.message);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void postProcessEvaluationContext() {
		final MessageExpressionConfigAttribute configAttribute = mock(MessageExpressionConfigAttribute.class);
		this.voter.setExpressionHandler(this.expressionHandler);
		given(this.expressionHandler.createEvaluationContext(this.authentication, this.message))
			.willReturn(this.evaluationContext);
		given(configAttribute.getAuthorizeExpression()).willReturn(this.expression);
		this.attributes = Arrays.<ConfigAttribute>asList(configAttribute);
		given(configAttribute.postProcess(this.evaluationContext, this.message)).willReturn(this.evaluationContext);
		given(this.expression.getValue(any(EvaluationContext.class), eq(Boolean.class))).willReturn(true);
		assertThat(this.voter.vote(this.authentication, this.message, this.attributes))
			.isEqualTo(AccessDecisionVoter.ACCESS_GRANTED);
		verify(configAttribute).postProcess(this.evaluationContext, this.message);
	}

}
