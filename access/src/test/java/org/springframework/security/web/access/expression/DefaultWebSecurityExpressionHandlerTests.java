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

package org.springframework.security.web.access.expression;

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
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterInvocation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
public class DefaultWebSecurityExpressionHandlerTests {

	@Mock
	private AuthenticationTrustResolver trustResolver;

	@Mock
	private Authentication authentication;

	@Mock
	private FilterInvocation invocation;

	private DefaultWebSecurityExpressionHandler handler;

	@BeforeEach
	public void setup() {
		this.handler = new DefaultWebSecurityExpressionHandler();
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
				mock(FilterInvocation.class));
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
		EvaluationContext context = this.handler.createEvaluationContext(this.authentication, this.invocation);
		assertThat(expression.getValue(context, Boolean.class)).isFalse();
		verify(this.trustResolver).isAnonymous(this.authentication);
	}

}
