/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.access.expression.method;

import static org.assertj.core.api.Assertions.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Method;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.Test;
import org.mockito.Mock;
import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.core.Authentication;

/**
 * @author shabarijonnalagadda
 *
 */
public class MethodSecurityEvaluationContextTests {

	@Mock
	private Authentication authentication;
	@Mock
	private MethodInvocation methodInvocation;
	@Mock
	private AuthenticationTrustResolver trustResolver;
	@Mock
	private Method method;

	@Test
	public void setVariableTest() {
		ParameterNameDiscoverer paramNameDiscoverer = mock(ParameterNameDiscoverer.class);
		when(paramNameDiscoverer.getParameterNames(method)).thenReturn( new String[] {null});

		NotNullVariableMethodSecurityEvaluationContext context= new NotNullVariableMethodSecurityEvaluationContext(
				mock(Authentication.class), mock(MethodInvocation.class), paramNameDiscoverer);

		context.lookupVariable("TESTVALUE");

		fail("name  should not be null");
	}

	private static class  NotNullVariableMethodSecurityEvaluationContext
			extends MethodSecurityEvaluationContext {

		public NotNullVariableMethodSecurityEvaluationContext(Authentication auth, MethodInvocation mi,
				ParameterNameDiscoverer parameterNameDiscoverer) {
			super(auth, mi, parameterNameDiscoverer);
		}

		@Override
		public void setVariable(String name, @Nullable Object value) {
			if (name == null)
				throw new IllegalArgumentException("name  should not be null");

			else
				setVariable(name, value);
		}
	}
}