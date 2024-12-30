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

package org.springframework.security.messaging.access.expression;

import java.util.function.Supplier;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.TypedValue;
import org.springframework.messaging.Message;
import org.springframework.messaging.support.GenericMessage;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
public class DefaultMessageSecurityExpressionHandlerTests {

	@Mock(answer = Answers.CALLS_REAL_METHODS)
	AuthenticationTrustResolver trustResolver;

	@Mock
	PermissionEvaluator permissionEvaluator;

	DefaultMessageSecurityExpressionHandler<Object> handler;

	Message<Object> message;

	Authentication authentication;

	@BeforeEach
	public void setup() {
		this.handler = new DefaultMessageSecurityExpressionHandler<>();
		this.message = new GenericMessage<>("");
		this.authentication = new AnonymousAuthenticationToken("key", "anonymous",
				AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
	}

	// SEC-2705
	@Test
	public void trustResolverPopulated() {
		EvaluationContext context = this.handler.createEvaluationContext(this.authentication, this.message);
		Expression expression = this.handler.getExpressionParser().parseExpression("authenticated");
		assertThat(ExpressionUtils.evaluateAsBoolean(expression, context)).isFalse();
	}

	@Test
	public void trustResolverNull() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.handler.setTrustResolver(null));
	}

	@Test
	public void trustResolverCustom() {
		this.handler.setTrustResolver(this.trustResolver);
		EvaluationContext context = this.handler.createEvaluationContext(this.authentication, this.message);
		Expression expression = this.handler.getExpressionParser().parseExpression("authenticated");
		given(this.trustResolver.isAnonymous(this.authentication)).willReturn(false);
		assertThat(ExpressionUtils.evaluateAsBoolean(expression, context)).isTrue();
	}

	@Test
	public void roleHierarchy() {
		this.authentication = new TestingAuthenticationToken("admin", "pass", "ROLE_ADMIN");
		RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
		roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");
		this.handler.setRoleHierarchy(roleHierarchy);
		EvaluationContext context = this.handler.createEvaluationContext(this.authentication, this.message);
		Expression expression = this.handler.getExpressionParser().parseExpression("hasRole('ROLE_USER')");
		assertThat(ExpressionUtils.evaluateAsBoolean(expression, context)).isTrue();
	}

	@Test
	public void permissionEvaluator() {
		this.handler.setPermissionEvaluator(this.permissionEvaluator);
		EvaluationContext context = this.handler.createEvaluationContext(this.authentication, this.message);
		Expression expression = this.handler.getExpressionParser().parseExpression("hasPermission(message, 'read')");
		given(this.permissionEvaluator.hasPermission(this.authentication, this.message, "read")).willReturn(true);
		assertThat(ExpressionUtils.evaluateAsBoolean(expression, context)).isTrue();
	}

	@Test
	public void createEvaluationContextSupplierAuthentication() {
		Supplier<Authentication> mockAuthenticationSupplier = mock(Supplier.class);
		given(mockAuthenticationSupplier.get()).willReturn(this.authentication);
		EvaluationContext context = this.handler.createEvaluationContext(mockAuthenticationSupplier, this.message);
		verifyNoInteractions(mockAuthenticationSupplier);
		assertThat(context.getRootObject()).extracting(TypedValue::getValue)
			.asInstanceOf(InstanceOfAssertFactories.type(MessageSecurityExpressionRoot.class))
			.extracting(SecurityExpressionRoot::getAuthentication)
			.isEqualTo(this.authentication);
		verify(mockAuthenticationSupplier).get();
	}

}
