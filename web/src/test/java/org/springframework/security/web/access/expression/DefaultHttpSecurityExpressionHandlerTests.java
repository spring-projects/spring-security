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

package org.springframework.security.web.access.expression;

import java.util.function.Supplier;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.context.support.StaticApplicationContext;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.TypedValue;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
public class DefaultHttpSecurityExpressionHandlerTests {

	@Mock
	private AuthenticationTrustResolver trustResolver;

	@Mock
	private Authentication authentication;

	@Mock
	private RequestAuthorizationContext context;

	private DefaultHttpSecurityExpressionHandler handler;

	@BeforeEach
	public void setup() {
		this.handler = new DefaultHttpSecurityExpressionHandler();
	}

	@AfterEach
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void expressionPropertiesAreResolvedAgainstAppContextBeans() {
		StaticApplicationContext appContext = new StaticApplicationContext();
		RootBeanDefinition bean = new RootBeanDefinition(SecurityConfig.class);
		bean.getConstructorArgumentValues().addGenericArgumentValue("ROLE_A");
		appContext.registerBeanDefinition("role", bean);
		this.handler.setApplicationContext(appContext);
		EvaluationContext ctx = this.handler.createEvaluationContext(mock(Authentication.class),
				mock(RequestAuthorizationContext.class));
		ExpressionParser parser = this.handler.getExpressionParser();
		assertThat(parser.parseExpression("@role.getAttribute() == 'ROLE_A'").getValue(ctx, Boolean.class)).isTrue();
		assertThat(parser.parseExpression("@role.attribute == 'ROLE_A'").getValue(ctx, Boolean.class)).isTrue();
	}

	@Test
	public void setTrustResolverNull() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.handler.setTrustResolver(null));
	}

	@Test
	public void createEvaluationContextCustomTrustResolver() {
		this.handler.setTrustResolver(this.trustResolver);
		Expression expression = this.handler.getExpressionParser().parseExpression("anonymous");
		EvaluationContext context = this.handler.createEvaluationContext(this.authentication, this.context);
		assertThat(expression.getValue(context, Boolean.class)).isFalse();
		verify(this.trustResolver).isAnonymous(this.authentication);
	}

	@Test
	public void createEvaluationContextSupplierAuthentication() {
		Supplier<Authentication> mockAuthenticationSupplier = mock(Supplier.class);
		given(mockAuthenticationSupplier.get()).willReturn(this.authentication);
		EvaluationContext context = this.handler.createEvaluationContext(mockAuthenticationSupplier, this.context);
		verifyNoInteractions(mockAuthenticationSupplier);
		assertThat(context.getRootObject()).extracting(TypedValue::getValue)
				.asInstanceOf(InstanceOfAssertFactories.type(WebSecurityExpressionRoot.class))
				.extracting(SecurityExpressionRoot::getAuthentication).isEqualTo(this.authentication);
		verify(mockAuthenticationSupplier).get();
	}

}
