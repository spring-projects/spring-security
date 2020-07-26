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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.messaging.Message;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.security.messaging.util.matcher.MessageMatcher;
import org.springframework.security.messaging.util.matcher.SimpDestinationMessageMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class MessageExpressionConfigAttributeTests {

	@Mock
	Expression expression;

	@Mock
	MessageMatcher<?> matcher;

	MessageExpressionConfigAttribute attribute;

	@Before
	public void setup() {
		this.attribute = new MessageExpressionConfigAttribute(this.expression, this.matcher);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullExpression() {
		new MessageExpressionConfigAttribute(null, this.matcher);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullMatcher() {
		new MessageExpressionConfigAttribute(this.expression, null);
	}

	@Test
	public void getAuthorizeExpression() {
		assertThat(this.attribute.getAuthorizeExpression()).isSameAs(this.expression);
	}

	@Test
	public void getAttribute() {
		assertThat(this.attribute.getAttribute()).isNull();
	}

	@Test
	public void toStringUsesExpressionString() {
		when(this.expression.getExpressionString()).thenReturn("toString");

		assertThat(this.attribute.toString()).isEqualTo(this.expression.getExpressionString());
	}

	@Test
	public void postProcessContext() {
		SimpDestinationMessageMatcher matcher = new SimpDestinationMessageMatcher("/topics/{topic}/**");
		Message<?> message = MessageBuilder.withPayload("M")
				.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/topics/someTopic/sub1").build();
		EvaluationContext context = mock(EvaluationContext.class);

		this.attribute = new MessageExpressionConfigAttribute(this.expression, matcher);
		this.attribute.postProcess(context, message);

		verify(context).setVariable("topic", "someTopic");
	}

}
