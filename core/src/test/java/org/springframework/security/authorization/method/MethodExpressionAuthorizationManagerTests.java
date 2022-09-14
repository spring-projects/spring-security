/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.authorization.method;

import org.junit.jupiter.api.Test;
import org.junit.platform.commons.util.ReflectionUtils;

import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.security.access.annotation.BusinessService;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.util.SimpleMethodInvocation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class MethodExpressionAuthorizationManagerTests {

	@Test
	void instantiateWhenExpressionStringNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new MethodExpressionAuthorizationManager(null))
				.withMessage("expressionString cannot be empty");
	}

	@Test
	void instantiateWhenExpressionStringEmptyThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new MethodExpressionAuthorizationManager(""))
				.withMessage("expressionString cannot be empty");
	}

	@Test
	void instantiateWhenExpressionStringBlankThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new MethodExpressionAuthorizationManager(" "))
				.withMessage("expressionString cannot be empty");
	}

	@Test
	void instantiateWhenExpressionHandlerNotSetThenDefaultUsed() {
		MethodExpressionAuthorizationManager manager = new MethodExpressionAuthorizationManager("hasRole('ADMIN')");
		assertThat(manager).extracting("expressionHandler").isInstanceOf(DefaultMethodSecurityExpressionHandler.class);
	}

	@Test
	void setExpressionHandlerWhenNullThenIllegalArgumentException() {
		MethodExpressionAuthorizationManager manager = new MethodExpressionAuthorizationManager("hasRole('ADMIN')");
		assertThatIllegalArgumentException().isThrownBy(() -> manager.setExpressionHandler(null))
				.withMessage("expressionHandler cannot be null");
	}

	@Test
	void setExpressionHandlerWhenNotNullThenVerifyExpressionHandler() {
		String expressionString = "hasRole('ADMIN')";
		MethodExpressionAuthorizationManager manager = new MethodExpressionAuthorizationManager(expressionString);
		DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
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
		MethodExpressionAuthorizationManager manager = new MethodExpressionAuthorizationManager("hasRole('ADMIN')");
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedAdmin,
				new SimpleMethodInvocation(new Object(),
						ReflectionUtils.getRequiredMethod(BusinessService.class, "someAdminMethod")));
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	void checkWhenExpressionHasRoleAdminConfiguredAndRoleUserThenDeniedDecision() {
		MethodExpressionAuthorizationManager manager = new MethodExpressionAuthorizationManager("hasRole('ADMIN')");
		AuthorizationDecision decision = manager.check(TestAuthentication::authenticatedUser,
				new SimpleMethodInvocation(new Object(),
						ReflectionUtils.getRequiredMethod(BusinessService.class, "someAdminMethod")));
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

}
