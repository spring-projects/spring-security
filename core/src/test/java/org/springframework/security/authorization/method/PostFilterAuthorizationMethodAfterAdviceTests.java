/*
 * Copyright 2002-2021 the original author or authors.
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

import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.Test;

import org.springframework.aop.MethodMatcher;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.intercept.method.MockMethodInvocation;
import org.springframework.security.access.method.MethodAuthorizationContext;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.authentication.TestAuthentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link PostFilterAuthorizationMethodAfterAdvice}.
 *
 * @author Evgeniy Cheban
 */
public class PostFilterAuthorizationMethodAfterAdviceTests {

	@Test
	public void setExpressionHandlerWhenNotNullThenSetsExpressionHandler() {
		MethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
		PostFilterAuthorizationMethodAfterAdvice advice = new PostFilterAuthorizationMethodAfterAdvice();
		advice.setExpressionHandler(expressionHandler);
		assertThat(advice).extracting("expressionHandler").isEqualTo(expressionHandler);
	}

	@Test
	public void setExpressionHandlerWhenNullThenException() {
		PostFilterAuthorizationMethodAfterAdvice advice = new PostFilterAuthorizationMethodAfterAdvice();
		assertThatIllegalArgumentException().isThrownBy(() -> advice.setExpressionHandler(null))
				.withMessage("expressionHandler cannot be null");
	}

	@Test
	public void methodMatcherWhenMethodHasNotPostFilterAnnotationThenNotMatches() throws Exception {
		PostFilterAuthorizationMethodAfterAdvice advice = new PostFilterAuthorizationMethodAfterAdvice();
		MethodMatcher methodMatcher = advice.getMethodMatcher();
		assertThat(methodMatcher.matches(TestClass.class.getMethod("doSomething"), TestClass.class)).isFalse();
	}

	@Test
	public void methodMatcherWhenMethodHasPostFilterAnnotationThenMatches() throws Exception {
		PostFilterAuthorizationMethodAfterAdvice advice = new PostFilterAuthorizationMethodAfterAdvice();
		MethodMatcher methodMatcher = advice.getMethodMatcher();
		assertThat(
				methodMatcher.matches(TestClass.class.getMethod("doSomethingArray", String[].class), TestClass.class))
						.isTrue();
	}

	@Test
	public void afterWhenArrayNotNullThenFilteredArray() throws Exception {
		String[] array = { "john", "bob" };
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingArray", new Class[] { String[].class }, new Object[] { array });
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(mockMethodInvocation,
				TestClass.class);
		PostFilterAuthorizationMethodAfterAdvice advice = new PostFilterAuthorizationMethodAfterAdvice();
		Object result = advice.after(TestAuthentication::authenticatedUser, methodAuthorizationContext, array);
		assertThat(result).asInstanceOf(InstanceOfAssertFactories.array(String[].class)).containsOnly("john");
	}

	public static class TestClass {

		public void doSomething() {

		}

		@PostFilter("filterObject == 'john'")
		public String[] doSomethingArray(String[] array) {
			return array;
		}

	}

}
