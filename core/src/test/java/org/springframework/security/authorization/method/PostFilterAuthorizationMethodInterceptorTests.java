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

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.springframework.aop.MethodMatcher;
import org.springframework.core.annotation.AnnotationConfigurationException;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.intercept.method.MockMethodInvocation;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link PostFilterAuthorizationMethodInterceptor}.
 *
 * @author Evgeniy Cheban
 */
public class PostFilterAuthorizationMethodInterceptorTests {

	@Before
	public void setUp() {
		SecurityContextHolder.getContext().setAuthentication(TestAuthentication.authenticatedUser());
	}

	@After
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

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
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingArrayClassLevel", new Class[] { String[].class }, new Object[] { array }) {
			@Override
			public Object proceed() {
				return array;
			}
		};
		PostFilterAuthorizationMethodInterceptor advice = new PostFilterAuthorizationMethodInterceptor();
		Object result = advice.invoke(methodInvocation);
		assertThat(result).asInstanceOf(InstanceOfAssertFactories.array(String[].class)).containsOnly("john");
	}

	@Test
	public void checkInheritedAnnotationsWhenDuplicatedThenAnnotationConfigurationException() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"inheritedAnnotations");
		PostFilterAuthorizationMethodInterceptor advice = new PostFilterAuthorizationMethodInterceptor();
		assertThatExceptionOfType(AnnotationConfigurationException.class)
				.isThrownBy(() -> advice.invoke(methodInvocation));
	}

	@Test
	public void checkInheritedAnnotationsWhenConflictingThenAnnotationConfigurationException() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new ConflictingAnnotations(),
				ConflictingAnnotations.class, "inheritedAnnotations");
		PostFilterAuthorizationMethodInterceptor advice = new PostFilterAuthorizationMethodInterceptor();
		assertThatExceptionOfType(AnnotationConfigurationException.class)
				.isThrownBy(() -> advice.invoke(methodInvocation));
	}

	@PostFilter("filterObject == 'john'")
	public static class TestClass implements InterfaceAnnotationsOne, InterfaceAnnotationsTwo {

		@PostFilter("filterObject == 'john'")
		public String[] doSomethingArray(String[] array) {
			return array;
		}

		public String[] doSomethingArrayClassLevel(String[] array) {
			return array;
		}

		@Override
		public void inheritedAnnotations() {

		}

	}

	public static class NoPostFilterClass {

		public void doSomething() {

		}

	}

	public static class ConflictingAnnotations implements InterfaceAnnotationsThree {

		@Override
		@PostFilter("filterObject == 'jack'")
		public void inheritedAnnotations() {

		}

	}

	public interface InterfaceAnnotationsOne {

		@PostFilter("filterObject == 'jim'")
		void inheritedAnnotations();

	}

	public interface InterfaceAnnotationsTwo {

		@PostFilter("filterObject == 'jane'")
		void inheritedAnnotations();

	}

	public interface InterfaceAnnotationsThree {

		@MyPostFilter
		void inheritedAnnotations();

	}

	@Retention(RetentionPolicy.RUNTIME)
	@PostFilter("filterObject == 'john'")
	public @interface MyPostFilter {

	}

}
