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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.internal.stubbing.answers.Returns;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 * @since 3.2
 */
@RunWith(MockitoJUnitRunner.class)
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

	@Before
	@SuppressWarnings("serial")
	public void setUp() throws Exception {
		this.originalSecurityContext = SecurityContextHolder.createEmptyContext();
		given(this.delegate.call()).willAnswer(new Returns(this.callableResult) {
			@Override
			public Object answer(InvocationOnMock invocation) throws Throwable {
				assertThat(SecurityContextHolder.getContext())
						.isEqualTo(DelegatingSecurityContextCallableTests.this.securityContext);
				return super.answer(invocation);
			}
		});
		this.executor = Executors.newFixedThreadPool(1);
	}

	@After
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullDelegate() {
		new DelegatingSecurityContextCallable<>(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullDelegateNonNullSecurityContext() {
		new DelegatingSecurityContextCallable<>(null, this.securityContext);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullDelegateAndSecurityContext() {
		new DelegatingSecurityContextCallable<>(null, null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullSecurityContext() {
		new DelegatingSecurityContextCallable<>(this.delegate, null);
	}

	@Test
	public void call() throws Exception {
		this.callable = new DelegatingSecurityContextCallable<>(this.delegate, this.securityContext);
		assertWrapped(this.callable);
	}

	@Test
	public void callDefaultSecurityContext() throws Exception {
		SecurityContextHolder.setContext(this.securityContext);
		this.callable = new DelegatingSecurityContextCallable<>(this.delegate);
		SecurityContextHolder.clearContext(); // ensure callable is what sets up the
												// SecurityContextHolder
		assertWrapped(this.callable);
	}

	// SEC-3031
	@Test
	public void callOnSameThread() throws Exception {
		this.originalSecurityContext = this.securityContext;
		SecurityContextHolder.setContext(this.originalSecurityContext);
		this.callable = new DelegatingSecurityContextCallable<>(this.delegate, this.securityContext);
		assertWrapped(this.callable.call());
	}

	@Test(expected = IllegalArgumentException.class)
	public void createNullDelegate() {
		DelegatingSecurityContextCallable.create(null, this.securityContext);
	}

	@Test(expected = IllegalArgumentException.class)
	public void createNullDelegateAndSecurityContext() {
		DelegatingSecurityContextRunnable.create(null, null);
	}

	@Test
	public void createNullSecurityContext() throws Exception {
		SecurityContextHolder.setContext(this.securityContext);
		this.callable = DelegatingSecurityContextCallable.create(this.delegate, null);
		SecurityContextHolder.clearContext(); // ensure callable is what sets up the
												// SecurityContextHolder
		assertWrapped(this.callable);
	}

	@Test
	public void create() throws Exception {
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
