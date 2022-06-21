/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.concurrent;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.internal.stubbing.answers.Returns;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.security.core.context.MockSecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 * @since 3.2
 */
@ExtendWith(MockitoExtension.class)
public class DelegatingSecurityContextCallableTests {

	@Mock
	private Callable<Object> delegate;

	@Mock
	private SecurityContext securityContext;

	@Mock
	private Object callableResult;

	private Callable<Object> callable;

	private ExecutorService executor;

	private SecurityContext originalSecurityContext;

	@BeforeEach
	@SuppressWarnings("serial")
	public void setUp() throws Exception {
		this.originalSecurityContext = SecurityContextHolder.createEmptyContext();
		this.executor = Executors.newFixedThreadPool(1);
	}

	private void givenDelegateCallWillAnswerWithCurrentSecurityContext() throws Exception {
		givenDelegateCallWillAnswerWithCurrentSecurityContext(SecurityContextHolder.getContextHolderStrategy());
	}

	private void givenDelegateCallWillAnswerWithCurrentSecurityContext(SecurityContextHolderStrategy strategy)
			throws Exception {
		given(this.delegate.call()).willAnswer(new Returns(this.callableResult) {
			@Override
			public Object answer(InvocationOnMock invocation) throws Throwable {
				assertThat(strategy.getContext())
						.isEqualTo(DelegatingSecurityContextCallableTests.this.securityContext);
				return super.answer(invocation);
			}
		});
	}

	@AfterEach
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void constructorNullDelegate() {
		assertThatIllegalArgumentException().isThrownBy(() -> new DelegatingSecurityContextCallable<>(null));
	}

	@Test
	public void constructorNullDelegateNonNullSecurityContext() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new DelegatingSecurityContextCallable<>(null, this.securityContext));
	}

	@Test
	public void constructorNullDelegateAndSecurityContext() {
		assertThatIllegalArgumentException().isThrownBy(() -> new DelegatingSecurityContextCallable<>(null, null));
	}

	@Test
	public void constructorNullSecurityContext() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new DelegatingSecurityContextCallable<>(this.delegate, null));
	}

	@Test
	public void call() throws Exception {
		givenDelegateCallWillAnswerWithCurrentSecurityContext();
		this.callable = new DelegatingSecurityContextCallable<>(this.delegate, this.securityContext);
		assertWrapped(this.callable);
	}

	@Test
	public void callDefaultSecurityContext() throws Exception {
		givenDelegateCallWillAnswerWithCurrentSecurityContext();
		SecurityContextHolder.setContext(this.securityContext);
		this.callable = new DelegatingSecurityContextCallable<>(this.delegate);
		// ensure callable is what sets up the SecurityContextHolder
		SecurityContextHolder.clearContext();
		assertWrapped(this.callable);
	}

	@Test
	public void callDefaultSecurityContextWithCustomSecurityContextHolderStrategy() throws Exception {
		SecurityContextHolderStrategy securityContextHolderStrategy = spy(new MockSecurityContextHolderStrategy());
		givenDelegateCallWillAnswerWithCurrentSecurityContext(securityContextHolderStrategy);
		securityContextHolderStrategy.setContext(this.securityContext);
		DelegatingSecurityContextCallable<Object> callable = new DelegatingSecurityContextCallable<>(this.delegate);
		callable.setSecurityContextHolderStrategy(securityContextHolderStrategy);
		this.callable = callable;
		// ensure callable is what sets up the SecurityContextHolder
		securityContextHolderStrategy.clearContext();
		assertWrapped(this.callable);
		verify(securityContextHolderStrategy, atLeastOnce()).getContext();
	}

	// SEC-3031
	@Test
	public void callOnSameThread() throws Exception {
		givenDelegateCallWillAnswerWithCurrentSecurityContext();
		this.originalSecurityContext = this.securityContext;
		SecurityContextHolder.setContext(this.originalSecurityContext);
		this.callable = new DelegatingSecurityContextCallable<>(this.delegate, this.securityContext);
		assertWrapped(this.callable.call());
	}

	@Test
	public void createNullDelegate() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> DelegatingSecurityContextCallable.create(null, this.securityContext));
	}

	@Test
	public void createNullDelegateAndSecurityContext() {
		assertThatIllegalArgumentException().isThrownBy(() -> DelegatingSecurityContextRunnable.create(null, null));
	}

	@Test
	public void createNullSecurityContext() throws Exception {
		givenDelegateCallWillAnswerWithCurrentSecurityContext();
		SecurityContextHolder.setContext(this.securityContext);
		this.callable = DelegatingSecurityContextCallable.create(this.delegate, null);
		// ensure callable is what sets up the SecurityContextHolder
		SecurityContextHolder.clearContext();
		assertWrapped(this.callable);
	}

	@Test
	public void create() throws Exception {
		givenDelegateCallWillAnswerWithCurrentSecurityContext();
		this.callable = DelegatingSecurityContextCallable.create(this.delegate, this.securityContext);
		assertWrapped(this.callable);
	}

	// SEC-2682
	@Test
	public void toStringDelegates() {
		this.callable = new DelegatingSecurityContextCallable<>(this.delegate, this.securityContext);
		assertThat(this.callable.toString()).isEqualTo(this.delegate.toString());
	}

	private void assertWrapped(Callable<Object> callable) throws Exception {
		Future<Object> submit = this.executor.submit(callable);
		assertWrapped(submit.get());
	}

	private void assertWrapped(Object callableResult) throws Exception {
		verify(this.delegate).call();
		assertThat(SecurityContextHolder.getContext()).isEqualTo(this.originalSecurityContext);
	}

}
