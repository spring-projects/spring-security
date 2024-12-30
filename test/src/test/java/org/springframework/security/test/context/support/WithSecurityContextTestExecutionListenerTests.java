/*
 * Copyright 2002-2018 the original author or authors.
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

import java.lang.reflect.Method;
import java.util.function.Supplier;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestContext;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 * @since 5.0
 */
@ExtendWith({ MockitoExtension.class, SpringExtension.class })
@ContextConfiguration(classes = WithSecurityContextTestExecutionListenerTests.NoOpConfiguration.class)
public class WithSecurityContextTestExecutionListenerTests {

	@Autowired
	private ApplicationContext applicationContext;

	private TestContext testContext;

	private WithSecurityContextTestExecutionListener listener = new WithSecurityContextTestExecutionListener();

	@BeforeEach
	public void setup() {
		this.testContext = mock(TestContext.class);
	}

	@AfterEach
	public void cleanup() {
		TestSecurityContextHolder.clearContext();
	}

	@Test
	public void beforeTestMethodWhenWithMockUserTestExecutionDefaultThenSecurityContextSet() throws Exception {
		Method testMethod = TheTest.class.getMethod("withMockUserDefault");
		given(this.testContext.getApplicationContext()).willReturn(this.applicationContext);
		given(this.testContext.getTestMethod()).willReturn(testMethod);
		this.listener.beforeTestMethod(this.testContext);
		assertThat(TestSecurityContextHolder.getContext().getAuthentication()).isNotNull();
		verify(this.testContext, never()).setAttribute(
				eq(WithSecurityContextTestExecutionListener.SECURITY_CONTEXT_ATTR_NAME), any(SecurityContext.class));
	}

	@Test
	public void beforeTestMethodWhenWithMockUserTestMethodThenSecurityContextSet() throws Exception {
		Method testMethod = TheTest.class.getMethod("withMockUserTestMethod");
		given(this.testContext.getApplicationContext()).willReturn(this.applicationContext);
		given(this.testContext.getTestMethod()).willReturn(testMethod);
		this.listener.beforeTestMethod(this.testContext);
		assertThat(TestSecurityContextHolder.getContext().getAuthentication()).isNotNull();
		verify(this.testContext, never()).setAttribute(
				eq(WithSecurityContextTestExecutionListener.SECURITY_CONTEXT_ATTR_NAME), any(SecurityContext.class));
	}

	@Test
	public void beforeTestMethodWhenWithMockUserTestExecutionThenTestContextSet() throws Exception {
		Method testMethod = TheTest.class.getMethod("withMockUserTestExecution");
		given(this.testContext.getApplicationContext()).willReturn(this.applicationContext);
		given(this.testContext.getTestMethod()).willReturn(testMethod);
		this.listener.beforeTestMethod(this.testContext);
		assertThat(TestSecurityContextHolder.getContext().getAuthentication()).isNull();
		verify(this.testContext).setAttribute(eq(WithSecurityContextTestExecutionListener.SECURITY_CONTEXT_ATTR_NAME),
				ArgumentMatchers.<Supplier<SecurityContext>>any());
	}

	@Test
	@SuppressWarnings("unchecked")
	public void beforeTestMethodWhenWithMockUserTestExecutionThenTestContextSupplierOk() throws Exception {
		Method testMethod = TheTest.class.getMethod("withMockUserTestExecution");
		given(this.testContext.getApplicationContext()).willReturn(this.applicationContext);
		given(this.testContext.getTestMethod()).willReturn(testMethod);
		this.listener.beforeTestMethod(this.testContext);
		ArgumentCaptor<Supplier<SecurityContext>> supplierCaptor = ArgumentCaptor.forClass(Supplier.class);
		verify(this.testContext).setAttribute(eq(WithSecurityContextTestExecutionListener.SECURITY_CONTEXT_ATTR_NAME),
				supplierCaptor.capture());
		assertThat(supplierCaptor.getValue().get().getAuthentication()).isNotNull();
	}

	@Test
	// gh-6591
	public void beforeTestMethodWhenTestExecutionThenDelayFactoryCreate() throws Exception {
		Method testMethod = TheTest.class.getMethod("withUserDetails");
		given(this.testContext.getApplicationContext()).willReturn(this.applicationContext);
		// do not set a UserDetailsService Bean so it would fail if looked up
		given(this.testContext.getTestMethod()).willReturn(testMethod);
		this.listener.beforeTestMethod(this.testContext);
		// bean lookup of UserDetailsService would fail if it has already been looked up
	}

	@Test
	public void beforeTestExecutionWhenTestContextNullThenSecurityContextNotSet() {
		this.listener.beforeTestExecution(this.testContext);
		assertThat(TestSecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void beforeTestExecutionWhenTestContextNotNullThenSecurityContextSet() {
		SecurityContextImpl securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(new TestingAuthenticationToken("user", "passsword", "ROLE_USER"));
		Supplier<SecurityContext> supplier = () -> securityContext;
		given(this.testContext.removeAttribute(WithSecurityContextTestExecutionListener.SECURITY_CONTEXT_ATTR_NAME))
			.willReturn(supplier);
		this.listener.beforeTestExecution(this.testContext);
		assertThat(TestSecurityContextHolder.getContext().getAuthentication())
			.isEqualTo(securityContext.getAuthentication());
	}

	@Configuration
	static class NoOpConfiguration {

	}

	static class TheTest {

		@WithMockUser(setupBefore = TestExecutionEvent.TEST_EXECUTION)
		public void withMockUserTestExecution() {
		}

		@WithMockUser(setupBefore = TestExecutionEvent.TEST_METHOD)
		public void withMockUserTestMethod() {
		}

		@WithMockUser
		public void withMockUserDefault() {
		}

		@WithUserDetails(setupBefore = TestExecutionEvent.TEST_EXECUTION)
		public void withUserDetails() {
		}

	}

}
