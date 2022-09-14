/*
 * Copyright 2002-2022 the original author or authors.
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

import org.aopalliance.intercept.MethodInvocation;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.aop.Pointcut;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.intercept.method.MockMethodInvocation;
import org.springframework.security.authorization.ReactiveAuthorizationManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link AuthorizationManagerAfterReactiveMethodInterceptor}.
 *
 * @author Evgeniy Cheban
 */
public class AuthorizationManagerAfterReactiveMethodInterceptorTests {

	@Test
	public void instantiateWhenPointcutNullThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new AuthorizationManagerAfterReactiveMethodInterceptor(null,
						mock(ReactiveAuthorizationManager.class)))
				.withMessage("pointcut cannot be null");
	}

	@Test
	public void instantiateWhenAuthorizationManagerNullThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new AuthorizationManagerAfterReactiveMethodInterceptor(mock(Pointcut.class), null))
				.withMessage("authorizationManager cannot be null");
	}

	@Test
	public void invokeMonoWhenMockReactiveAuthorizationManagerThenVerify() throws Throwable {
		MethodInvocation mockMethodInvocation = spy(
				new MockMethodInvocation(new Sample(), Sample.class.getDeclaredMethod("mono")));
		given(mockMethodInvocation.proceed()).willReturn(Mono.just("john"));
		ReactiveAuthorizationManager<MethodInvocationResult> mockReactiveAuthorizationManager = mock(
				ReactiveAuthorizationManager.class);
		given(mockReactiveAuthorizationManager.verify(any(), any())).willReturn(Mono.empty());
		AuthorizationManagerAfterReactiveMethodInterceptor interceptor = new AuthorizationManagerAfterReactiveMethodInterceptor(
				Pointcut.TRUE, mockReactiveAuthorizationManager);
		Object result = interceptor.invoke(mockMethodInvocation);
		assertThat(result).asInstanceOf(InstanceOfAssertFactories.type(Mono.class)).extracting(Mono::block)
				.isEqualTo("john");
		verify(mockReactiveAuthorizationManager).verify(any(), any());
	}

	@Test
	public void invokeFluxWhenMockReactiveAuthorizationManagerThenVerify() throws Throwable {
		MethodInvocation mockMethodInvocation = spy(
				new MockMethodInvocation(new Sample(), Sample.class.getDeclaredMethod("flux")));
		given(mockMethodInvocation.proceed()).willReturn(Flux.just("john", "bob"));
		ReactiveAuthorizationManager<MethodInvocationResult> mockReactiveAuthorizationManager = mock(
				ReactiveAuthorizationManager.class);
		given(mockReactiveAuthorizationManager.verify(any(), any())).willReturn(Mono.empty());
		AuthorizationManagerAfterReactiveMethodInterceptor interceptor = new AuthorizationManagerAfterReactiveMethodInterceptor(
				Pointcut.TRUE, mockReactiveAuthorizationManager);
		Object result = interceptor.invoke(mockMethodInvocation);
		assertThat(result).asInstanceOf(InstanceOfAssertFactories.type(Flux.class)).extracting(Flux::collectList)
				.extracting(Mono::block, InstanceOfAssertFactories.list(String.class)).containsExactly("john", "bob");
		verify(mockReactiveAuthorizationManager, times(2)).verify(any(), any());
	}

	@Test
	public void invokeWhenMockReactiveAuthorizationManagerDeniedThenAccessDeniedException() throws Throwable {
		MethodInvocation mockMethodInvocation = spy(
				new MockMethodInvocation(new Sample(), Sample.class.getDeclaredMethod("mono")));
		given(mockMethodInvocation.proceed()).willReturn(Mono.just("john"));
		ReactiveAuthorizationManager<MethodInvocationResult> mockReactiveAuthorizationManager = mock(
				ReactiveAuthorizationManager.class);
		given(mockReactiveAuthorizationManager.verify(any(), any()))
				.willReturn(Mono.error(new AccessDeniedException("Access Denied")));
		AuthorizationManagerAfterReactiveMethodInterceptor interceptor = new AuthorizationManagerAfterReactiveMethodInterceptor(
				Pointcut.TRUE, mockReactiveAuthorizationManager);
		Object result = interceptor.invoke(mockMethodInvocation);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> assertThat(result)
				.asInstanceOf(InstanceOfAssertFactories.type(Mono.class)).extracting(Mono::block))
				.withMessage("Access Denied");
		verify(mockReactiveAuthorizationManager).verify(any(), any());
	}

	class Sample {

		Mono<String> mono() {
			return Mono.just("john");
		}

		Flux<String> flux() {
			return Flux.just("john", "bob");
		}

	}

}
