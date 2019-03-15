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
package org.springframework.security.access.expression.method;

import static org.mockito.Mockito.verify;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

@RunWith(MockitoJUnitRunner.class)
public class DefaultMethodSecurityExpressionHandlerTests {
	private DefaultMethodSecurityExpressionHandler handler;

	@Mock
	private Authentication authentication;
	@Mock
	private MethodInvocation methodInvocation;
	@Mock
	private AuthenticationTrustResolver trustResolver;

	@Before
	public void setup() {
		handler = new DefaultMethodSecurityExpressionHandler();
	}

	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test(expected = IllegalArgumentException.class)
	public void setTrustResolverNull() {
		handler.setTrustResolver(null);
	}

	@Test
	public void createEvaluationContextCustomTrustResolver() {
		handler.setTrustResolver(trustResolver);

		Expression expression = handler.getExpressionParser()
				.parseExpression("anonymous");
		EvaluationContext context = handler.createEvaluationContext(authentication,
				methodInvocation);
		expression.getValue(context, Boolean.class);

		verify(trustResolver).isAnonymous(authentication);
	}
}
