/*
 * Copyright 2002-2014 the original author or authors.
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
package org.springframework.security.test.context.support;

import java.lang.annotation.Annotation;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.test.context.TestContext;
import org.springframework.test.context.TestExecutionListener;
import org.springframework.test.context.jdbc.SqlScriptsTestExecutionListener;
import org.springframework.test.context.support.AbstractTestExecutionListener;
import org.springframework.util.ReflectionUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

@RunWith(MockitoJUnitRunner.class)
public class WithSecurityContextTestExcecutionListenerTests {

	private ConfigurableApplicationContext context;

	@Mock
	private TestContext testContext;

	private WithSecurityContextTestExecutionListener listener;

	@Before
	public void setup() {
		this.listener = new WithSecurityContextTestExecutionListener();
		this.context = new AnnotationConfigApplicationContext(Config.class);
	}

	@After
	public void cleanup() {
		TestSecurityContextHolder.clearContext();
		if (this.context != null) {
			this.context.close();
		}
	}

	@Test
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public void beforeTestMethodNullSecurityContextNoError() throws Exception {
		Class testClass = FakeTest.class;
		given(this.testContext.getTestClass()).willReturn(testClass);
		given(this.testContext.getTestMethod()).willReturn(ReflectionUtils.findMethod(testClass, "testNoAnnotation"));

		this.listener.beforeTestMethod(this.testContext);
	}

	@Test
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public void beforeTestMethodNoApplicationContext() throws Exception {
		Class testClass = FakeTest.class;
		given(this.testContext.getApplicationContext()).willThrow(new IllegalStateException());
		given(this.testContext.getTestMethod()).willReturn(ReflectionUtils.findMethod(testClass, "testWithMockUser"));

		this.listener.beforeTestMethod(this.testContext);

		assertThat(TestSecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("user");
	}

	// gh-3962
	@Test
	public void withSecurityContextAfterSqlScripts() {
		SqlScriptsTestExecutionListener sql = new SqlScriptsTestExecutionListener();
		WithSecurityContextTestExecutionListener security = new WithSecurityContextTestExecutionListener();

		List<TestExecutionListener> listeners = Arrays.asList(security, sql);

		AnnotationAwareOrderComparator.sort(listeners);

		assertThat(listeners).containsExactly(sql, security);
	}

	// SEC-2709
	@Test
	public void orderOverridden() {
		AbstractTestExecutionListener otherListener = new AbstractTestExecutionListener() {
		};

		List<TestExecutionListener> listeners = new ArrayList<>();
		listeners.add(otherListener);
		listeners.add(this.listener);

		AnnotationAwareOrderComparator.sort(listeners);

		assertThat(listeners).containsSequence(this.listener, otherListener);
	}

	@Test
	// gh-3837
	public void handlesGenericAnnotation() throws Exception {
		Method method = ReflectionUtils.findMethod(WithSecurityContextTestExcecutionListenerTests.class,
				"handlesGenericAnnotationTestMethod");
		TestContext testContext = mock(TestContext.class);
		given(testContext.getTestMethod()).willReturn(method);
		given(testContext.getApplicationContext()).willThrow(new IllegalStateException(""));

		this.listener.beforeTestMethod(testContext);

		assertThat(SecurityContextHolder.getContext().getAuthentication().getPrincipal())
				.isInstanceOf(WithSuperClassWithSecurityContext.class);
	}

	@WithSuperClassWithSecurityContext
	public void handlesGenericAnnotationTestMethod() {
	}

	@Retention(RetentionPolicy.RUNTIME)
	@WithSecurityContext(factory = SuperClassWithSecurityContextFactory.class)
	@interface WithSuperClassWithSecurityContext {

		String username() default "WithSuperClassWithSecurityContext";

	}

	static class SuperClassWithSecurityContextFactory implements WithSecurityContextFactory<Annotation> {

		@Override
		public SecurityContext createSecurityContext(Annotation annotation) {
			SecurityContext context = SecurityContextHolder.createEmptyContext();
			context.setAuthentication(new TestingAuthenticationToken(annotation, "NA"));
			return context;
		}

	}

	static class FakeTest {

		public void testNoAnnotation() {
		}

		@WithMockUser
		public void testWithMockUser() {

		}

	}

	@Configuration
	static class Config {

	}

}
