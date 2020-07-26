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

import java.lang.reflect.Method;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.ReflectionUtils;

import static org.mockito.Mockito.doReturn;

/**
 * @author shabarijonnalagadda
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class MethodSecurityEvaluationContextTests {

	@Mock
	private ParameterNameDiscoverer paramNameDiscoverer;

	@Mock
	private Authentication authentication;

	@Mock
	private MethodInvocation methodInvocation;

	@Test
	public void lookupVariableWhenParameterNameNullThenNotSet() {
		Class<String> type = String.class;
		Method method = ReflectionUtils.findMethod(String.class, "contains", CharSequence.class);
		doReturn(new String[] { null }).when(this.paramNameDiscoverer).getParameterNames(method);
		doReturn(new Object[] { null }).when(this.methodInvocation).getArguments();
		doReturn(type).when(this.methodInvocation).getThis();
		doReturn(method).when(this.methodInvocation).getMethod();
		NotNullVariableMethodSecurityEvaluationContext context = new NotNullVariableMethodSecurityEvaluationContext(
				this.authentication, this.methodInvocation, this.paramNameDiscoverer);
		context.lookupVariable("testVariable");
	}

	private static class NotNullVariableMethodSecurityEvaluationContext extends MethodSecurityEvaluationContext {

		NotNullVariableMethodSecurityEvaluationContext(Authentication auth, MethodInvocation mi,
				ParameterNameDiscoverer parameterNameDiscoverer) {
			super(auth, mi, parameterNameDiscoverer);
		}

		@Override
		public void setVariable(String name, @Nullable Object value) {
			if (name == null) {
				throw new IllegalArgumentException("name  should not be null");
			}
			else {
				super.setVariable(name, value);
			}
		}

	}

}
