/*
 * Copyright 2002-2016 the original author or authors.
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
import org.springframework.expression.Expression;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class MessageExpressionConfigAttributeTests {
	@Mock
	Expression expression;

	MessageExpressionConfigAttribute attribute;

	@Before
	public void setup() {
		attribute = new MessageExpressionConfigAttribute(expression);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullExpression() {
		new MessageExpressionConfigAttribute(null);
	}

	@Test
	public void getAuthorizeExpression() {
		assertThat(attribute.getAuthorizeExpression()).isSameAs(expression);
	}

	@Test
	public void getAttribute() {
		assertThat(attribute.getAttribute()).isNull();
	}

	@Test
	public void toStringUsesExpressionString() {
		when(expression.getExpressionString()).thenReturn("toString");

		assertThat(attribute.toString()).isEqualTo(expression.getExpressionString());
	}
}
