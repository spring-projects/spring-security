/*
 * Copyright 2002-2019 the original author or authors.
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

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.security.access.intercept.method.MockMethodInvocation;
import org.springframework.security.access.prepost.PreInvocationAttribute;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests {@link ExpressionBasedPreInvocationAdvice}
 *
 * @author Maksim Vinogradov
 * @since 5.2
 */
@RunWith(MockitoJUnitRunner.class)
public class ExpressionBasedPreInvocationAdviceTests {

	@Mock
	private Authentication authentication;

	private ExpressionBasedPreInvocationAdvice expressionBasedPreInvocationAdvice;

	@Before
	public void setUp() {
		this.expressionBasedPreInvocationAdvice = new ExpressionBasedPreInvocationAdvice();
	}

	@Test
	public void findFilterTargetNameProvidedButNotMatch() throws Exception {
		PreInvocationAttribute attribute = new PreInvocationExpressionAttribute("true", "filterTargetDoesNotMatch",
				null);
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingCollection", new Class[] { List.class }, new Object[] { new ArrayList<>() });
		assertThatIllegalArgumentException().isThrownBy(
				() -> this.expressionBasedPreInvocationAdvice.before(this.authentication, methodInvocation, attribute));
	}

	@Test
	public void findFilterTargetNameProvidedArrayUnsupported() throws Exception {
		PreInvocationAttribute attribute = new PreInvocationExpressionAttribute("true", "param", null);
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingArray", new Class[] { String[].class }, new Object[] { new String[0] });
		assertThatIllegalArgumentException().isThrownBy(
				() -> this.expressionBasedPreInvocationAdvice.before(this.authentication, methodInvocation, attribute));
	}

	@Test
	public void findFilterTargetNameProvided() throws Exception {
		PreInvocationAttribute attribute = new PreInvocationExpressionAttribute("true", "param", null);
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingCollection", new Class[] { List.class }, new Object[] { new ArrayList<>() });
		boolean result = this.expressionBasedPreInvocationAdvice.before(this.authentication, methodInvocation,
				attribute);
		assertThat(result).isTrue();
	}

	@Test
	public void findFilterTargetNameNotProvidedArrayUnsupported() throws Exception {
		PreInvocationAttribute attribute = new PreInvocationExpressionAttribute("true", "", null);
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingArray", new Class[] { String[].class }, new Object[] { new String[0] });
		assertThatIllegalArgumentException().isThrownBy(
				() -> this.expressionBasedPreInvocationAdvice.before(this.authentication, methodInvocation, attribute));
	}

	@Test
	public void findFilterTargetNameNotProvided() throws Exception {
		PreInvocationAttribute attribute = new PreInvocationExpressionAttribute("true", "", null);
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingCollection", new Class[] { List.class }, new Object[] { new ArrayList<>() });
		boolean result = this.expressionBasedPreInvocationAdvice.before(this.authentication, methodInvocation,
				attribute);
		assertThat(result).isTrue();
	}

	@Test
	public void findFilterTargetNameNotProvidedTypeNotSupported() throws Exception {
		PreInvocationAttribute attribute = new PreInvocationExpressionAttribute("true", "", null);
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingString", new Class[] { String.class }, new Object[] { "param" });
		assertThatIllegalArgumentException().isThrownBy(
				() -> this.expressionBasedPreInvocationAdvice.before(this.authentication, methodInvocation, attribute));
	}

	@Test
	public void findFilterTargetNameNotProvidedMethodAcceptMoreThenOneArgument() throws Exception {
		PreInvocationAttribute attribute = new PreInvocationExpressionAttribute("true", "", null);
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingTwoArgs", new Class[] { String.class, List.class },
				new Object[] { "param", new ArrayList<>() });
		assertThatIllegalArgumentException().isThrownBy(
				() -> this.expressionBasedPreInvocationAdvice.before(this.authentication, methodInvocation, attribute));
	}

	private class TestClass {

		public Boolean doSomethingCollection(List<?> param) {
			return Boolean.TRUE;
		}

		public Boolean doSomethingArray(String[] param) {
			return Boolean.TRUE;
		}

		public Boolean doSomethingString(String param) {
			return Boolean.TRUE;
		}

		public Boolean doSomethingTwoArgs(String param, List<?> list) {
			return Boolean.TRUE;
		}

	}

}
