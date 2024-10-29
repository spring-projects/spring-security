/*
 * Copyright 2002-2024 the original author or authors.
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
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.ReactiveAuthorizationManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link AuthorizationManagerBeforeReactiveMethodInterceptor}.
 *
 * @author Evgeniy Cheban
 */
public class AuthorizationManagerBeforeReactiveMethodInterceptorTests {

	@Test
	public void instantiateWhenPointcutNullThenException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new AuthorizationManagerBeforeReactiveMethodInterceptor(null,
					mock(ReactiveAuthorizationManager.class)))
			.withMessage("pointcut cannot be null");

	}

	@Test
	public void instantiateWhenAuthorizationManagerNullThenException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new AuthorizationManagerBeforeReactiveMethodInterceptor(mock(Pointcut.class), null))
			.withMessage("authorizationManager cannot be null");
	}

	@Test
	public void invokeMonoWhenMockReactiveAuthorizationManagerThenVerify() throws Throwable {
		MethodInvocation mockMethodInvocation = spy(
				new MockMethodInvocation(new Sample(), Sample.class.getDeclaredMethod("mono")));
		given(mockMethodInvocation.proceed()).willReturn(Mono.just("john"));
		ReactiveAuthorizationManager<MethodInvocation> mockReactiveAuthorizationManager = mock(
				ReactiveAuthorizationManager.class);
		given(mockReactiveAuthorizationManager.check(any(), eq(mockMethodInvocation)))
			.willReturn(Mono.just(new AuthorizationDecision(true)));
		given(mockReactiveAuthorizationManager.authorize(any(), any())).willCallRealMethod();
		AuthorizationManagerBeforeReactiveMethodInterceptor interceptor = new AuthorizationManagerBeforeReactiveMethodInterceptor(
				Pointcut.TRUE, mockReactiveAuthorizationManager);
		Object result = interceptor.invoke(mockMethodInvocation);
		assertThat(result).asInstanceOf(InstanceOfAssertFactories.type(Mono.class))
			.extracting(Mono::block)
			.isEqualTo("john");
		verify(mockReactiveAuthorizationManager).check(any(), eq(mockMethodInvocation));
	}

	@Test
	public void invokeFluxWhenMockReactiveAuthorizationManagerThenVerify() throws Throwable {
		MethodInvocation mockMethodInvocation = spy(
				new MockMethodInvocation(new Sample(), Sample.class.getDeclaredMethod("flux")));
		given(mockMethodInvocation.proceed()).willReturn(Flux.just("john", "bob"));
		ReactiveAuthorizationManager<MethodInvocation> mockReactiveAuthorizationManager = mock(
				ReactiveAuthorizationManager.class);
		given(mockReactiveAuthorizationManager.check(any(), eq(mockMethodInvocation)))
			.willReturn(Mono.just(new AuthorizationDecision((true))));
		given(mockReactiveAuthorizationManager.authorize(any(), any())).willCallRealMethod();
		AuthorizationManagerBeforeReactiveMethodInterceptor interceptor = new AuthorizationManagerBeforeReactiveMethodInterceptor(
				Pointcut.TRUE, mockReactiveAuthorizationManager);
		Object result = interceptor.invoke(mockMethodInvocation);
		assertThat(result).asInstanceOf(InstanceOfAssertFactories.type(Flux.class))
			.extracting(Flux::collectList)
			.extracting(Mono::block, InstanceOfAssertFactories.list(String.class))
			.containsExactly("john", "bob");
		verify(mockReactiveAuthorizationManager).check(any(), eq(mockMethodInvocation));
	}

	@Test
	public void invokeWhenMockReactiveAuthorizationManagerDeniedThenAccessDeniedException() throws Throwable {
		MethodInvocation mockMethodInvocation = spy(
				new MockMethodInvocation(new Sample(), Sample.class.getDeclaredMethod("mono")));
		given(mockMethodInvocation.proceed()).willReturn(Mono.just("john"));
		ReactiveAuthorizationManager<MethodInvocation> mockReactiveAuthorizationManager = mock(
				ReactiveAuthorizationManager.class);
		given(mockReactiveAuthorizationManager.check(any(), eq(mockMethodInvocation)))
			.willReturn(Mono.just(new AuthorizationDecision(false)));
		given(mockReactiveAuthorizationManager.authorize(any(), any())).willCallRealMethod();
		AuthorizationManagerBeforeReactiveMethodInterceptor interceptor = new AuthorizationManagerBeforeReactiveMethodInterceptor(
				Pointcut.TRUE, mockReactiveAuthorizationManager);
		Object result = interceptor.invoke(mockMethodInvocation);
		assertThatExceptionOfType(AccessDeniedException.class)
			.isThrownBy(() -> assertThat(result).asInstanceOf(InstanceOfAssertFactories.type(Mono.class))
				.extracting(Mono::block))
			.withMessage("Access Denied");
		verify(mockReactiveAuthorizationManager).check(any(), eq(mockMethodInvocation));
	}

	@Test
	public void invokeMonoWhenDeniedAndPostProcessorThenInvokePostProcessor() throws Throwable {
		MethodInvocation mockMethodInvocation = spy(
				new MockMethodInvocation(new Sample(), Sample.class.getDeclaredMethod("mono")));
		given(mockMethodInvocation.proceed()).willReturn(Mono.just("john"));
		HandlingReactiveAuthorizationManager mockReactiveAuthorizationManager = mock(
				HandlingReactiveAuthorizationManager.class);
		given(mockReactiveAuthorizationManager.check(any(), eq(mockMethodInvocation))).willReturn(Mono.empty());
		given(mockReactiveAuthorizationManager.authorize(any(), any())).willCallRealMethod();
		given(mockReactiveAuthorizationManager.handleDeniedInvocation(any(), any(AuthorizationResult.class)))
			.willReturn("***");
		AuthorizationManagerBeforeReactiveMethodInterceptor interceptor = new AuthorizationManagerBeforeReactiveMethodInterceptor(
				Pointcut.TRUE, mockReactiveAuthorizationManager);
		Object result = interceptor.invoke(mockMethodInvocation);
		assertThat(result).asInstanceOf(InstanceOfAssertFactories.type(Mono.class))
			.extracting(Mono::block)
			.isEqualTo("***");
		verify(mockReactiveAuthorizationManager).check(any(), eq(mockMethodInvocation));
	}

	@Test
	public void invokeMonoWhenDeniedAndMonoPostProcessorThenInvokePostProcessor() throws Throwable {
		MethodInvocation mockMethodInvocation = spy(
				new MockMethodInvocation(new Sample(), Sample.class.getDeclaredMethod("mono")));
		given(mockMethodInvocation.proceed()).willReturn(Mono.just("john"));
		HandlingReactiveAuthorizationManager mockReactiveAuthorizationManager = mock(
				HandlingReactiveAuthorizationManager.class);
		given(mockReactiveAuthorizationManager.check(any(), eq(mockMethodInvocation))).willReturn(Mono.empty());
		given(mockReactiveAuthorizationManager.authorize(any(), any())).willCallRealMethod();
		given(mockReactiveAuthorizationManager.handleDeniedInvocation(any(), any(AuthorizationResult.class)))
			.willReturn(Mono.just("***"));
		AuthorizationManagerBeforeReactiveMethodInterceptor interceptor = new AuthorizationManagerBeforeReactiveMethodInterceptor(
				Pointcut.TRUE, mockReactiveAuthorizationManager);
		Object result = interceptor.invoke(mockMethodInvocation);
		assertThat(result).asInstanceOf(InstanceOfAssertFactories.type(Mono.class))
			.extracting(Mono::block)
			.isEqualTo("***");
		verify(mockReactiveAuthorizationManager).check(any(), eq(mockMethodInvocation));
	}

	@Test
	public void invokeFluxWhenDeniedAndPostProcessorThenInvokePostProcessor() throws Throwable {
		MethodInvocation mockMethodInvocation = spy(
				new MockMethodInvocation(new Sample(), Sample.class.getDeclaredMethod("flux")));
		given(mockMethodInvocation.proceed()).willReturn(Flux.just("john", "bob"));
		HandlingReactiveAuthorizationManager mockReactiveAuthorizationManager = mock(
				HandlingReactiveAuthorizationManager.class);
		given(mockReactiveAuthorizationManager.check(any(), eq(mockMethodInvocation))).willReturn(Mono.empty());
		given(mockReactiveAuthorizationManager.authorize(any(), any())).willCallRealMethod();
		given(mockReactiveAuthorizationManager.handleDeniedInvocation(any(), any(AuthorizationResult.class)))
			.willReturn(Mono.just("***"));
		AuthorizationManagerBeforeReactiveMethodInterceptor interceptor = new AuthorizationManagerBeforeReactiveMethodInterceptor(
				Pointcut.TRUE, mockReactiveAuthorizationManager);
		Object result = interceptor.invoke(mockMethodInvocation);
		assertThat(result).asInstanceOf(InstanceOfAssertFactories.type(Flux.class))
			.extracting(Flux::collectList)
			.extracting(Mono::block, InstanceOfAssertFactories.list(String.class))
			.containsExactly("***");
		verify(mockReactiveAuthorizationManager).check(any(), eq(mockMethodInvocation));
	}

	@Test
	public void invokeMonoWhenEmptyDecisionThenInvokeDefaultPostProcessor() throws Throwable {
		MethodInvocation mockMethodInvocation = spy(
				new MockMethodInvocation(new Sample(), Sample.class.getDeclaredMethod("mono")));
		given(mockMethodInvocation.proceed()).willReturn(Mono.just("john"));
		ReactiveAuthorizationManager<MethodInvocation> mockReactiveAuthorizationManager = mock(
				ReactiveAuthorizationManager.class);
		given(mockReactiveAuthorizationManager.check(any(), eq(mockMethodInvocation))).willReturn(Mono.empty());
		given(mockReactiveAuthorizationManager.authorize(any(), any())).willCallRealMethod();
		AuthorizationManagerBeforeReactiveMethodInterceptor interceptor = new AuthorizationManagerBeforeReactiveMethodInterceptor(
				Pointcut.TRUE, mockReactiveAuthorizationManager);
		Object result = interceptor.invoke(mockMethodInvocation);
		assertThatExceptionOfType(AuthorizationDeniedException.class)
			.isThrownBy(() -> assertThat(result).asInstanceOf(InstanceOfAssertFactories.type(Mono.class))
				.extracting(Mono::block))
			.withMessage("Access Denied");
		verify(mockReactiveAuthorizationManager).check(any(), eq(mockMethodInvocation));
	}

	@Test
	public void invokeFluxWhenEmptyDecisionThenInvokeDefaultPostProcessor() throws Throwable {
		MethodInvocation mockMethodInvocation = spy(
				new MockMethodInvocation(new Sample(), Sample.class.getDeclaredMethod("flux")));
		given(mockMethodInvocation.proceed()).willReturn(Flux.just("john", "bob"));
		ReactiveAuthorizationManager<MethodInvocation> mockReactiveAuthorizationManager = mock(
				ReactiveAuthorizationManager.class);
		given(mockReactiveAuthorizationManager.check(any(), eq(mockMethodInvocation))).willReturn(Mono.empty());
		given(mockReactiveAuthorizationManager.authorize(any(), any())).willCallRealMethod();
		AuthorizationManagerBeforeReactiveMethodInterceptor interceptor = new AuthorizationManagerBeforeReactiveMethodInterceptor(
				Pointcut.TRUE, mockReactiveAuthorizationManager);
		Object result = interceptor.invoke(mockMethodInvocation);
		assertThatExceptionOfType(AuthorizationDeniedException.class)
			.isThrownBy(() -> assertThat(result).asInstanceOf(InstanceOfAssertFactories.type(Flux.class))
				.extracting(Flux::blockFirst))
			.withMessage("Access Denied");
		verify(mockReactiveAuthorizationManager).check(any(), eq(mockMethodInvocation));
	}

	@Test
	public void invokeWhenCustomAuthorizationDeniedExceptionThenThrows() throws Throwable {
		MethodInvocation mockMethodInvocation = spy(
				new MockMethodInvocation(new Sample(), Sample.class.getDeclaredMethod("flux")));
		ReactiveAuthorizationManager<MethodInvocation> manager = mock(ReactiveAuthorizationManager.class);
		given(manager.check(any(), any()))
			.willThrow(new MyAuthzDeniedException("denied", new AuthorizationDecision(false)));
		given(manager.authorize(any(), any())).willCallRealMethod();
		AuthorizationManagerBeforeReactiveMethodInterceptor advice = new AuthorizationManagerBeforeReactiveMethodInterceptor(
				Pointcut.TRUE, manager);
		assertThatExceptionOfType(MyAuthzDeniedException.class)
			.isThrownBy(() -> ((Mono<?>) advice.invoke(mockMethodInvocation)).block());
	}

	interface HandlingReactiveAuthorizationManager
			extends ReactiveAuthorizationManager<MethodInvocation>, MethodAuthorizationDeniedHandler {

	}

	class Sample {

		Mono<String> mono() {
			return Mono.just("john");
		}

		Flux<String> flux() {
			return Flux.just("john", "bob");
		}

	}

	static class MyAuthzDeniedException extends AuthorizationDeniedException {

		MyAuthzDeniedException(String msg, AuthorizationResult authorizationResult) {
			super(msg, authorizationResult);
		}

	}

}
