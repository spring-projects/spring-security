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

import java.util.Arrays;
import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.After;
import org.junit.Test;

import org.springframework.aop.Pointcut;
import org.springframework.security.access.intercept.method.MockMethodInvocation;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link DelegatingAuthorizationMethodInterceptor}.
 *
 * @author Evgeniy Cheban
 */
public class DelegatingAuthorizationMethodInterceptorTests {

	@After
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void invokeWhenAuthenticatedThenVerifyAdvicesUsage() throws Throwable {
		Authentication authentication = TestAuthentication.authenticatedUser();
		SecurityContextHolder.setContext(new SecurityContextImpl(authentication));
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingString");
		AuthorizationMethodInterceptor interceptor = mock(AuthorizationMethodInterceptor.class);
		given(interceptor.getPointcut()).willReturn(Pointcut.TRUE);
		given(interceptor.invoke(any(), any(AuthorizationMethodInvocation.class))).willReturn("abc");
		DelegatingAuthorizationMethodInterceptor chain = new DelegatingAuthorizationMethodInterceptor(
				Arrays.asList(interceptor));
		Object result = chain.invoke(mockMethodInvocation);
		assertThat(result).isEqualTo("abc");
		verify(interceptor).invoke(any(), any(AuthorizationMethodInvocation.class));
	}

	@Test
	public void invokeWhenNotAuthenticatedThenAuthenticationCredentialsNotFoundException() throws Throwable {
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingString");
		AuthorizationMethodInterceptor first = new AuthorizationMethodInterceptor() {
			@Override
			public Pointcut getPointcut() {
				return Pointcut.TRUE;
			}

			@Override
			public Object invoke(Supplier<Authentication> authentication, MethodInvocation mi) {
				return authentication.get();
			}
		};
		AuthorizationMethodInterceptor second = mock(AuthorizationMethodInterceptor.class);
		given(second.getPointcut()).willReturn(Pointcut.TRUE);
		DelegatingAuthorizationMethodInterceptor interceptor = new DelegatingAuthorizationMethodInterceptor(
				Arrays.asList(first, second));
		assertThatExceptionOfType(AuthenticationCredentialsNotFoundException.class)
				.isThrownBy(() -> interceptor.invoke(mockMethodInvocation))
				.withMessage("An Authentication object was not found in the SecurityContext");
		verify(second, times(0)).invoke(any(), any());
	}

	public static class TestClass {

		public String doSomethingString() {
			return null;
		}

	}

}
