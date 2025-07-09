/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.web.access.expression;

import org.junit.jupiter.api.Test;

import org.springframework.context.support.GenericApplicationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link WebExpressionAuthorizationManager}.
 *
 * @author Evgeniy Cheban
 */
class WebExpressionAuthorizationManagerTests {

	@Test
	void instantiateWhenExpressionStringNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new WebExpressionAuthorizationManager(null))
			.withMessage("expressionString cannot be empty");
	}

	@Test
	void instantiateWhenExpressionStringEmptyThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new WebExpressionAuthorizationManager(""))
			.withMessage("expressionString cannot be empty");
	}

	@Test
	void instantiateWhenExpressionStringBlankThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new WebExpressionAuthorizationManager(" "))
			.withMessage("expressionString cannot be empty");
	}

	@Test
	void instantiateWhenExpressionHandlerNotSetThenDefaultUsed() {
		WebExpressionAuthorizationManager manager = new WebExpressionAuthorizationManager("hasRole('ADMIN')");
		assertThat(manager).extracting("expressionHandler").isInstanceOf(DefaultHttpSecurityExpressionHandler.class);
	}

	@Test
	void setExpressionHandlerWhenNullThenIllegalArgumentException() {
		WebExpressionAuthorizationManager manager = new WebExpressionAuthorizationManager("hasRole('ADMIN')");
		assertThatIllegalArgumentException().isThrownBy(() -> manager.setExpressionHandler(null))
			.withMessage("expressionHandler cannot be null");
	}

	@Test
	void setExpressionHandlerWhenNotNullThenVerifyExpressionHandler() {
		String expressionString = "hasRole('ADMIN')";
		WebExpressionAuthorizationManager manager = new WebExpressionAuthorizationManager(expressionString);
		DefaultHttpSecurityExpressionHandler expressionHandler = new DefaultHttpSecurityExpressionHandler();
		ExpressionParser mockExpressionParser = mock(ExpressionParser.class);
		Expression mockExpression = mock(Expression.class);
		given(mockExpressionParser.parseExpression(expressionString)).willReturn(mockExpression);
		expressionHandler.setExpressionParser(mockExpressionParser);
		manager.setExpressionHandler(expressionHandler);
		assertThat(manager).extracting("expressionHandler").isEqualTo(expressionHandler);
		assertThat(manager).extracting("expression").isEqualTo(mockExpression);
		verify(mockExpressionParser).parseExpression(expressionString);
	}

	@Test
	void checkWhenExpressionHasRoleAdminConfiguredAndRoleAdminThenGrantedDecision() {
		WebExpressionAuthorizationManager manager = new WebExpressionAuthorizationManager("hasRole('ADMIN')");
		AuthorizationResult decision = manager.authorize(TestAuthentication::authenticatedAdmin,
				new RequestAuthorizationContext(new MockHttpServletRequest()));
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	void checkWhenExpressionHasRoleAdminConfiguredAndRoleUserThenDeniedDecision() {
		WebExpressionAuthorizationManager manager = new WebExpressionAuthorizationManager("hasRole('ADMIN')");
		AuthorizationResult decision = manager.authorize(TestAuthentication::authenticatedUser,
				new RequestAuthorizationContext(new MockHttpServletRequest()));
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	void authorizeWhenDefaultsThenEvaluatesExpressionsReferencingBeans() {
		GenericApplicationContext context = new GenericApplicationContext();
		context.registerBean("bean", WebExpressionAuthorizationManagerTests.class, () -> this);
		context.refresh();
		WebExpressionAuthorizationManager.Builder builder = WebExpressionAuthorizationManager.withDefaults();
		builder.setApplicationContext(context);
		WebExpressionAuthorizationManager manager = builder
			.expression("@bean.class.simpleName.startsWith('WebExpression')");
		AuthorizationResult result = manager.authorize(TestAuthentication::authenticatedUser,
				new RequestAuthorizationContext(new MockHttpServletRequest()));
		assertThat(result.isGranted()).isTrue();
	}

	@Test
	void authorizeWhenDefaultsAsBeanThenEvaluatesExpressionsReferencingBeans() {
		GenericApplicationContext context = new GenericApplicationContext();
		context.registerBean("bean", WebExpressionAuthorizationManagerTests.class, () -> this);
		context.registerBean("builder", WebExpressionAuthorizationManager.Builder.class,
				WebExpressionAuthorizationManager::withDefaults);
		context.refresh();
		WebExpressionAuthorizationManager.Builder builder = context
			.getBean(WebExpressionAuthorizationManager.Builder.class);
		WebExpressionAuthorizationManager manager = builder
			.expression("@bean.class.simpleName.startsWith('WebExpression')");
		AuthorizationResult result = manager.authorize(TestAuthentication::authenticatedUser,
				new RequestAuthorizationContext(new MockHttpServletRequest()));
		assertThat(result.isGranted()).isTrue();
	}

	@Test
	void authorizeWhenExpressionHandlerHasBeanProviderThenEvaluatesExpressionsReferencingBeans() {
		GenericApplicationContext context = new GenericApplicationContext();
		context.registerBean("bean", WebExpressionAuthorizationManagerTests.class, () -> this);
		context.refresh();
		DefaultHttpSecurityExpressionHandler expressionHandler = new DefaultHttpSecurityExpressionHandler();
		expressionHandler.setApplicationContext(context);
		WebExpressionAuthorizationManager manager = WebExpressionAuthorizationManager
			.withExpressionHandler(expressionHandler)
			.expression("@bean.class.simpleName.startsWith('WebExpression')");
		AuthorizationResult result = manager.authorize(TestAuthentication::authenticatedUser,
				new RequestAuthorizationContext(new MockHttpServletRequest()));
		assertThat(result.isGranted()).isTrue();
	}

}
