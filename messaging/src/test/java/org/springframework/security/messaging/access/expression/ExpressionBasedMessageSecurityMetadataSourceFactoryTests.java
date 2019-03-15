/*
 * Copyright 2002-2017 the original author or authors.
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.springframework.security.messaging.access.expression.ExpressionBasedMessageSecurityMetadataSourceFactory.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.messaging.Message;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.messaging.access.intercept.MessageSecurityMetadataSource;
import org.springframework.security.messaging.util.matcher.MessageMatcher;

import java.util.Collection;
import java.util.LinkedHashMap;

@RunWith(MockitoJUnitRunner.class)
public class ExpressionBasedMessageSecurityMetadataSourceFactoryTests {
	@Mock
	MessageMatcher<Object> matcher1;
	@Mock
	MessageMatcher<Object> matcher2;
	@Mock
	Message<Object> message;
	@Mock
	Authentication authentication;

	String expression1;

	String expression2;

	LinkedHashMap<MessageMatcher<?>, String> matcherToExpression;

	MessageSecurityMetadataSource source;

	MessageSecurityExpressionRoot rootObject;

	@Before
	public void setup() {
		expression1 = "permitAll";
		expression2 = "denyAll";
		matcherToExpression = new LinkedHashMap<MessageMatcher<?>, String>();
		matcherToExpression.put(matcher1, expression1);
		matcherToExpression.put(matcher2, expression2);

		source = createExpressionMessageMetadataSource(matcherToExpression);
		rootObject = new MessageSecurityExpressionRoot(authentication, message);
	}

	@Test
	public void createExpressionMessageMetadataSourceNoMatch() {

		Collection<ConfigAttribute> attrs = source.getAttributes(message);

		assertThat(attrs).isNull();
	}

	@Test
	public void createExpressionMessageMetadataSourceMatchFirst() {
		when(matcher1.matches(message)).thenReturn(true);

		Collection<ConfigAttribute> attrs = source.getAttributes(message);

		assertThat(attrs).hasSize(1);
		ConfigAttribute attr = attrs.iterator().next();
		assertThat(attr).isInstanceOf(MessageExpressionConfigAttribute.class);
		assertThat(
				((MessageExpressionConfigAttribute) attr).getAuthorizeExpression()
						.getValue(rootObject)).isEqualTo(true);
	}

	@Test
	public void createExpressionMessageMetadataSourceMatchSecond() {
		when(matcher2.matches(message)).thenReturn(true);

		Collection<ConfigAttribute> attrs = source.getAttributes(message);

		assertThat(attrs).hasSize(1);
		ConfigAttribute attr = attrs.iterator().next();
		assertThat(attr).isInstanceOf(MessageExpressionConfigAttribute.class);
		assertThat(
				((MessageExpressionConfigAttribute) attr).getAuthorizeExpression()
						.getValue(rootObject)).isEqualTo(false);
	}
}
