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

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import org.springframework.aop.MethodMatcher;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.intercept.method.MockMethodInvocation;
import org.springframework.security.access.method.MethodAuthorizationContext;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.authentication.TestAuthentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

/**
 * Tests for {@link PreFilterAuthorizationMethodBeforeAdvice}.
 *
 * @author Evgeniy Cheban
 */
public class PreFilterAuthorizationMethodBeforeAdviceTests {

	@Test
	public void setExpressionHandlerWhenNotNullThenSetsExpressionHandler() {
		MethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
		PreFilterAuthorizationMethodBeforeAdvice advice = new PreFilterAuthorizationMethodBeforeAdvice();
		advice.setExpressionHandler(expressionHandler);
		assertThat(advice).extracting("expressionHandler").isEqualTo(expressionHandler);
	}

	@Test
	public void setExpressionHandlerWhenNullThenException() {
		PreFilterAuthorizationMethodBeforeAdvice advice = new PreFilterAuthorizationMethodBeforeAdvice();
		assertThatIllegalArgumentException().isThrownBy(() -> advice.setExpressionHandler(null))
				.withMessage("expressionHandler cannot be null");
	}

	@Test
	public void methodMatcherWhenMethodHasNotPreFilterAnnotationThenNotMatches() throws Exception {
		PreFilterAuthorizationMethodBeforeAdvice advice = new PreFilterAuthorizationMethodBeforeAdvice();
		MethodMatcher methodMatcher = advice.getMethodMatcher();
		assertThat(methodMatcher.matches(TestClass.class.getMethod("doSomething"), TestClass.class)).isFalse();
	}

	@Test
	public void methodMatcherWhenMethodHasPreFilterAnnotationThenMatches() throws Exception {
		PreFilterAuthorizationMethodBeforeAdvice advice = new PreFilterAuthorizationMethodBeforeAdvice();
		MethodMatcher methodMatcher = advice.getMethodMatcher();
		assertThat(methodMatcher.matches(TestClass.class.getMethod("doSomethingListFilterTargetMatch", List.class),
				TestClass.class)).isTrue();
	}

	@Test
	public void findFilterTargetWhenNameProvidedAndNotMatchThenException() throws Exception {
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingListFilterTargetNotMatch", new Class[] { List.class }, new Object[] { new ArrayList<>() });
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(mockMethodInvocation,
				TestClass.class);
		PreFilterAuthorizationMethodBeforeAdvice advice = new PreFilterAuthorizationMethodBeforeAdvice();
		assertThatIllegalArgumentException()
				.isThrownBy(() -> advice.before(TestAuthentication::authenticatedUser, methodAuthorizationContext))
				.withMessage(
						"Filter target was null, or no argument with name 'filterTargetNotMatch' found in method.");
	}

	@Test
	public void findFilterTargetWhenNameProvidedAndMatchAndNullThenException() throws Exception {
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingListFilterTargetMatch", new Class[] { List.class }, new Object[] { null });
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(mockMethodInvocation,
				TestClass.class);
		PreFilterAuthorizationMethodBeforeAdvice advice = new PreFilterAuthorizationMethodBeforeAdvice();
		assertThatIllegalArgumentException()
				.isThrownBy(() -> advice.before(TestAuthentication::authenticatedUser, methodAuthorizationContext))
				.withMessage("Filter target was null, or no argument with name 'list' found in method.");
	}

	@Test
	public void findFilterTargetWhenNameProvidedAndMatchAndNotNullThenFiltersList() throws Exception {
		List<String> list = new ArrayList<>();
		list.add("john");
		list.add("bob");
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingListFilterTargetMatch", new Class[] { List.class }, new Object[] { list });
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(mockMethodInvocation,
				TestClass.class);
		PreFilterAuthorizationMethodBeforeAdvice advice = new PreFilterAuthorizationMethodBeforeAdvice();
		advice.before(TestAuthentication::authenticatedUser, methodAuthorizationContext);
		assertThat(list).hasSize(1);
		assertThat(list.get(0)).isEqualTo("john");
	}

	@Test
	public void findFilterTargetWhenNameNotProvidedAndSingleArgListNullThenException() throws Exception {
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingListFilterTargetNotProvided", new Class[] { List.class }, new Object[] { null });
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(mockMethodInvocation,
				TestClass.class);
		PreFilterAuthorizationMethodBeforeAdvice advice = new PreFilterAuthorizationMethodBeforeAdvice();
		assertThatIllegalArgumentException()
				.isThrownBy(() -> advice.before(TestAuthentication::authenticatedUser, methodAuthorizationContext))
				.withMessage("Filter target was null. Make sure you passing the correct value in the method argument.");
	}

	@Test
	public void findFilterTargetWhenNameNotProvidedAndSingleArgListThenFiltersList() throws Exception {
		List<String> list = new ArrayList<>();
		list.add("john");
		list.add("bob");
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingListFilterTargetNotProvided", new Class[] { List.class }, new Object[] { list });
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(mockMethodInvocation,
				TestClass.class);
		PreFilterAuthorizationMethodBeforeAdvice advice = new PreFilterAuthorizationMethodBeforeAdvice();
		advice.before(TestAuthentication::authenticatedUser, methodAuthorizationContext);
		assertThat(list).hasSize(1);
		assertThat(list.get(0)).isEqualTo("john");
	}

	@Test
	public void findFilterTargetWhenNameNotProvidedAndSingleArgArrayThenException() throws Exception {
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingArrayFilterTargetNotProvided", new Class[] { String[].class },
				new Object[] { new String[] {} });
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(mockMethodInvocation,
				TestClass.class);
		PreFilterAuthorizationMethodBeforeAdvice advice = new PreFilterAuthorizationMethodBeforeAdvice();
		assertThatIllegalStateException()
				.isThrownBy(() -> advice.before(TestAuthentication::authenticatedUser, methodAuthorizationContext))
				.withMessage(
						"Pre-filtering on array types is not supported. Using a Collection will solve this problem.");
	}

	@Test
	public void findFilterTargetWhenNameNotProvidedAndNotSingleArgThenException() throws Exception {
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingTwoArgsFilterTargetNotProvided", new Class[] { String.class, List.class },
				new Object[] { "", new ArrayList<>() });
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(mockMethodInvocation,
				TestClass.class);
		PreFilterAuthorizationMethodBeforeAdvice advice = new PreFilterAuthorizationMethodBeforeAdvice();
		assertThatIllegalStateException()
				.isThrownBy(() -> advice.before(TestAuthentication::authenticatedUser, methodAuthorizationContext))
				.withMessage("Unable to determine the method argument for filtering. Specify the filter target.");
	}

	public static class TestClass {

		public void doSomething() {

		}

		@PreFilter(value = "filterObject == 'john'", filterTarget = "filterTargetNotMatch")
		public List<String> doSomethingListFilterTargetNotMatch(List<String> list) {
			return list;
		}

		@PreFilter(value = "filterObject == 'john'", filterTarget = "list")
		public List<String> doSomethingListFilterTargetMatch(List<String> list) {
			return list;
		}

		@PreFilter("filterObject == 'john'")
		public List<String> doSomethingListFilterTargetNotProvided(List<String> list) {
			return list;
		}

		@PreFilter("filterObject == 'john'")
		public String[] doSomethingArrayFilterTargetNotProvided(String[] array) {
			return array;
		}

		@PreFilter("filterObject == 'john'")
		public List<String> doSomethingTwoArgsFilterTargetNotProvided(String s, List<String> list) {
			return list;
		}

	}

}
