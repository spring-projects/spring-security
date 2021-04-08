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

import java.util.Collections;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.Test;

import org.springframework.aop.MethodMatcher;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.intercept.method.MockMethodInvocation;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.authentication.TestAuthentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link PostFilterAuthorizationMethodInterceptor}.
 *
 * @author Evgeniy Cheban
 */
public class PostFilterAuthorizationMethodInterceptorTests {

	@Test
	public void setExpressionHandlerWhenNotNullThenSetsExpressionHandler() {
		MethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
		PostFilterAuthorizationMethodInterceptor advice = new PostFilterAuthorizationMethodInterceptor();
		advice.setExpressionHandler(expressionHandler);
		assertThat(advice).extracting("expressionHandler").isEqualTo(expressionHandler);
	}

	@Test
	public void setExpressionHandlerWhenNullThenException() {
		PostFilterAuthorizationMethodInterceptor advice = new PostFilterAuthorizationMethodInterceptor();
		assertThatIllegalArgumentException().isThrownBy(() -> advice.setExpressionHandler(null))
				.withMessage("expressionHandler cannot be null");
	}

	@Test
	public void methodMatcherWhenMethodHasNotPostFilterAnnotationThenNotMatches() throws Exception {
		PostFilterAuthorizationMethodInterceptor advice = new PostFilterAuthorizationMethodInterceptor();
		MethodMatcher methodMatcher = advice.getPointcut().getMethodMatcher();
		assertThat(methodMatcher.matches(NoPostFilterClass.class.getMethod("doSomething"), NoPostFilterClass.class))
				.isFalse();
	}

	@Test
	public void methodMatcherWhenMethodHasPostFilterAnnotationThenMatches() throws Exception {
		PostFilterAuthorizationMethodInterceptor advice = new PostFilterAuthorizationMethodInterceptor();
		MethodMatcher methodMatcher = advice.getPointcut().getMethodMatcher();
		assertThat(
				methodMatcher.matches(TestClass.class.getMethod("doSomethingArray", String[].class), TestClass.class))
						.isTrue();
	}

	@Test
	public void afterWhenArrayNotNullThenFilteredArray() throws Throwable {
		String[] array = { "john", "bob" };
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingArrayClassLevel", new Class[] { String[].class }, new Object[] { array }) {
			@Override
			public Object proceed() {
				return array;
			}
		};
		PostFilterAuthorizationMethodInterceptor advice = new PostFilterAuthorizationMethodInterceptor();
		AuthorizationMethodInvocation methodInvocation = new AuthorizationMethodInvocation(
				TestAuthentication::authenticatedUser, mockMethodInvocation, Collections.emptyList());
		Object result = advice.invoke(TestAuthentication::authenticatedUser, methodInvocation);
		assertThat(result).asInstanceOf(InstanceOfAssertFactories.array(String[].class)).containsOnly("john");
	}

	@PostFilter("filterObject == 'john'")
	public static class TestClass {

		@PostFilter("filterObject == 'john'")
		public String[] doSomethingArray(String[] array) {
			return array;
		}

		public String[] doSomethingArrayClassLevel(String[] array) {
			return array;
		}

	}

	public static class NoPostFilterClass {

		public void doSomething() {

		}

	}

}
