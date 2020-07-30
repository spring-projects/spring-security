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

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import org.springframework.core.task.SyncTaskExecutor;
import org.springframework.core.task.support.ExecutorServiceAdapter;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.willAnswer;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 * @since 3.2
 */
@RunWith(MockitoJUnitRunner.class)
public class DelegatingSecurityContextRunnableTests {

	@Mock
	private Runnable delegate;

	@Mock
	private SecurityContext securityContext;

	@Mock
	private Object callableResult;

	private Runnable runnable;

	private ExecutorService executor;

	private SecurityContext originalSecurityContext;

	@Before
	public void setUp() {
		this.originalSecurityContext = SecurityContextHolder.createEmptyContext();
		willAnswer((Answer<Object>) (invocation) -> {
			assertThat(SecurityContextHolder.getContext()).isEqualTo(this.securityContext);
			return null;
		}).given(this.delegate).run();

		this.executor = Executors.newFixedThreadPool(1);
	}

	@After
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullDelegate() {
		new DelegatingSecurityContextRunnable(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullDelegateNonNullSecurityContext() {
		new DelegatingSecurityContextRunnable(null, this.securityContext);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullDelegateAndSecurityContext() {
		new DelegatingSecurityContextRunnable(null, null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullSecurityContext() {
		new DelegatingSecurityContextRunnable(this.delegate, null);
	}

	@Test
	public void call() throws Exception {
		this.runnable = new DelegatingSecurityContextRunnable(this.delegate, this.securityContext);
		assertWrapped(this.runnable);
	}

	@Test
	public void callDefaultSecurityContext() throws Exception {
		SecurityContextHolder.setContext(this.securityContext);
		this.runnable = new DelegatingSecurityContextRunnable(this.delegate);
		SecurityContextHolder.clearContext(); // ensure runnable is what sets up the
												// SecurityContextHolder
		assertWrapped(this.runnable);
	}

	// SEC-3031
	@Test
	public void callOnSameThread() throws Exception {
		this.originalSecurityContext = this.securityContext;
		SecurityContextHolder.setContext(this.originalSecurityContext);
		this.executor = synchronousExecutor();
		this.runnable = new DelegatingSecurityContextRunnable(this.delegate, this.securityContext);
		assertWrapped(this.runnable);
	}

	@Test(expected = IllegalArgumentException.class)
	public void createNullDelegate() {
		DelegatingSecurityContextRunnable.create(null, this.securityContext);
	}

	@Test(expected = IllegalArgumentException.class)
	public void createNullDelegateAndSecurityContext() {
		DelegatingSecurityContextRunnable.create(null, null);
	}

	@Test
	public void createNullSecurityContext() throws Exception {
		SecurityContextHolder.setContext(this.securityContext);
		this.runnable = DelegatingSecurityContextRunnable.create(this.delegate, null);
		SecurityContextHolder.clearContext(); // ensure runnable is what sets up the
												// SecurityContextHolder
		assertWrapped(this.runnable);
	}

	@Test
	public void create() throws Exception {
		this.runnable = DelegatingSecurityContextRunnable.create(this.delegate, this.securityContext);
		assertWrapped(this.runnable);
	}

	// SEC-2682
	@Test
	public void toStringDelegates() {
		this.runnable = new DelegatingSecurityContextRunnable(this.delegate, this.securityContext);
		assertThat(this.runnable.toString()).isEqualTo(this.delegate.toString());
	}

	private void assertWrapped(Runnable runnable) throws Exception {
		Future<?> submit = this.executor.submit(runnable);
		submit.get();
		verify(this.delegate).run();
		assertThat(SecurityContextHolder.getContext()).isEqualTo(this.originalSecurityContext);
	}

	private static ExecutorService synchronousExecutor() {
		return new ExecutorServiceAdapter(new SyncTaskExecutor());
	}

}
