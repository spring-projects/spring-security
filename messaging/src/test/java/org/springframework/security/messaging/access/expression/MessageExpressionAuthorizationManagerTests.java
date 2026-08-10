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

import org.junit.jupiter.api.Test;

import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.messaging.support.GenericMessage;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.messaging.access.intercept.MessageAuthorizationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link MessageExpressionAuthorizationManager}.
 */
class MessageExpressionAuthorizationManagerTests {

	@Test
	void instantiateWhenExpressionStringNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new MessageExpressionAuthorizationManager(null))
			.withMessage("expressionString cannot be empty");
	}

	@Test
	void instantiateWhenExpressionStringEmptyThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new MessageExpressionAuthorizationManager(""))
			.withMessage("expressionString cannot be empty");
	}

	@Test
	void instantiateWhenExpressionStringBlankThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new MessageExpressionAuthorizationManager(" "))
			.withMessage("expressionString cannot be empty");
	}

	@Test
	void withSecurityExpressionHandlerWhenNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> MessageExpressionAuthorizationManager.withSecurityExpressionHandler(null))
			.withMessage("expressionHandler cannot be null");
	}

	@Test
	void instantiateWhenExpressionHandlerNotSetThenDefaultUsed() {
		MessageExpressionAuthorizationManager manager = new MessageExpressionAuthorizationManager("hasRole('ADMIN')");
		assertThat(manager).extracting("expressionHandler")
			.isInstanceOf(MessageAuthorizationContextSecurityExpressionHandler.class);
	}

	@Test
	void withSecurityExpressionHandlerWhenNotNullThenVerifyExpressionHandler() {
		String expressionString = "hasRole('ADMIN')";
		SecurityExpressionHandler<MessageAuthorizationContext<?>> expressionHandler = mock(
				SecurityExpressionHandler.class);
		ExpressionParser expressionParser = mock(ExpressionParser.class);
		Expression expression = mock(Expression.class);
		given(expressionHandler.getExpressionParser()).willReturn(expressionParser);
		given(expressionParser.parseExpression(expressionString)).willReturn(expression);
		MessageExpressionAuthorizationManager manager = MessageExpressionAuthorizationManager
			.withSecurityExpressionHandler(expressionHandler)
			.expression(expressionString);
		assertThat(manager).extracting("expressionHandler").isEqualTo(expressionHandler);
		assertThat(manager).extracting("expression").isEqualTo(expression);
		verify(expressionParser).parseExpression(expressionString);
	}

	@Test
	void authorizeWhenExpressionHasRoleAdminAndRoleAdminThenGrantedDecision() {
		MessageExpressionAuthorizationManager manager = new MessageExpressionAuthorizationManager("hasRole('ADMIN')");
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("admin", "password", "ROLE_ADMIN");
		AuthorizationResult result = manager.authorize(() -> authentication,
				new MessageAuthorizationContext<>(new GenericMessage<>("message")));
		assertThat(result).isNotNull();
		assertThat(result.isGranted()).isTrue();
	}

	@Test
	void authorizeWhenExpressionHasRoleAdminAndRoleUserThenDeniedDecision() {
		MessageExpressionAuthorizationManager manager = new MessageExpressionAuthorizationManager("hasRole('ADMIN')");
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		AuthorizationResult result = manager.authorize(() -> authentication,
				new MessageAuthorizationContext<>(new GenericMessage<>("message")));
		assertThat(result).isNotNull();
		assertThat(result.isGranted()).isFalse();
	}

}
