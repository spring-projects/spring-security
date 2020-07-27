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

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

/**
 * Abstract class for testing {@link DelegatingSecurityContextExecutorService} which
 * allows customization of how {@link DelegatingSecurityContextExecutorService} and its
 * mocks are created.
 *
 * @author Rob Winch
 * @since 3.2
 * @see CurrentDelegatingSecurityContextExecutorServiceTests
 * @see ExplicitDelegatingSecurityContextExecutorServiceTests
 */
public abstract class AbstractDelegatingSecurityContextExecutorServiceTests
		extends AbstractDelegatingSecurityContextExecutorTests {

	@Mock
	private Future<Object> expectedFutureObject;

	@Mock
	private Object resultArg;

	protected DelegatingSecurityContextExecutorService executor;

	@Before
	public final void setUpExecutorService() {
		this.executor = create();
	}

	@Override
	@Test(expected = IllegalArgumentException.class)
	public void constructorNullDelegate() {
		new DelegatingSecurityContextExecutorService(null);
	}

	@Test
	public void shutdown() {
		this.executor.shutdown();
		verify(this.delegate).shutdown();
	}

	@Test
	public void shutdownNow() {
		List<Runnable> result = this.executor.shutdownNow();
		verify(this.delegate).shutdownNow();
		assertThat(result).isEqualTo(this.delegate.shutdownNow()).isNotNull();
	}

	@Test
	public void isShutdown() {
		boolean result = this.executor.isShutdown();
		verify(this.delegate).isShutdown();
		assertThat(result).isEqualTo(this.delegate.isShutdown()).isNotNull();
	}

	@Test
	public void isTerminated() {
		boolean result = this.executor.isTerminated();
		verify(this.delegate).isTerminated();
		assertThat(result).isEqualTo(this.delegate.isTerminated()).isNotNull();
	}

	@Test
	public void awaitTermination() throws InterruptedException {
		boolean result = this.executor.awaitTermination(1, TimeUnit.SECONDS);
		verify(this.delegate).awaitTermination(1, TimeUnit.SECONDS);
		assertThat(result).isEqualTo(this.delegate.awaitTermination(1, TimeUnit.SECONDS)).isNotNull();
	}

	@Test
	public void submitCallable() {
		given(this.delegate.submit(this.wrappedCallable)).willReturn(this.expectedFutureObject);
		Future<Object> result = this.executor.submit(this.callable);
		verify(this.delegate).submit(this.wrappedCallable);
		assertThat(result).isEqualTo(this.expectedFutureObject);
	}

	@Test
	public void submitRunnableWithResult() {
		given(this.delegate.submit(this.wrappedRunnable, this.resultArg)).willReturn(this.expectedFutureObject);
		Future<Object> result = this.executor.submit(this.runnable, this.resultArg);
		verify(this.delegate).submit(this.wrappedRunnable, this.resultArg);
		assertThat(result).isEqualTo(this.expectedFutureObject);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void submitRunnable() {
		given((Future<Object>) this.delegate.submit(this.wrappedRunnable)).willReturn(this.expectedFutureObject);
		Future<?> result = this.executor.submit(this.runnable);
		verify(this.delegate).submit(this.wrappedRunnable);
		assertThat(result).isEqualTo(this.expectedFutureObject);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void invokeAll() throws Exception {
		List<Future<Object>> exectedResult = Arrays.asList(this.expectedFutureObject);
		List<Callable<Object>> wrappedCallables = Arrays.asList(this.wrappedCallable);
		given(this.delegate.invokeAll(wrappedCallables)).willReturn(exectedResult);
		List<Future<Object>> result = this.executor.invokeAll(Arrays.asList(this.callable));
		verify(this.delegate).invokeAll(wrappedCallables);
		assertThat(result).isEqualTo(exectedResult);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void invokeAllTimeout() throws Exception {
		List<Future<Object>> exectedResult = Arrays.asList(this.expectedFutureObject);
		List<Callable<Object>> wrappedCallables = Arrays.asList(this.wrappedCallable);
		given(this.delegate.invokeAll(wrappedCallables, 1, TimeUnit.SECONDS)).willReturn(exectedResult);
		List<Future<Object>> result = this.executor.invokeAll(Arrays.asList(this.callable), 1, TimeUnit.SECONDS);
		verify(this.delegate).invokeAll(wrappedCallables, 1, TimeUnit.SECONDS);
		assertThat(result).isEqualTo(exectedResult);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void invokeAny() throws Exception {
		List<Future<Object>> exectedResult = Arrays.asList(this.expectedFutureObject);
		List<Callable<Object>> wrappedCallables = Arrays.asList(this.wrappedCallable);
		given(this.delegate.invokeAny(wrappedCallables)).willReturn(exectedResult);
		Object result = this.executor.invokeAny(Arrays.asList(this.callable));
		verify(this.delegate).invokeAny(wrappedCallables);
		assertThat(result).isEqualTo(exectedResult);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void invokeAnyTimeout() throws Exception {
		List<Future<Object>> exectedResult = Arrays.asList(this.expectedFutureObject);
		List<Callable<Object>> wrappedCallables = Arrays.asList(this.wrappedCallable);
		given(this.delegate.invokeAny(wrappedCallables, 1, TimeUnit.SECONDS)).willReturn(exectedResult);
		Object result = this.executor.invokeAny(Arrays.asList(this.callable), 1, TimeUnit.SECONDS);
		verify(this.delegate).invokeAny(wrappedCallables, 1, TimeUnit.SECONDS);
		assertThat(result).isEqualTo(exectedResult);
	}

	@Override
	protected abstract DelegatingSecurityContextExecutorService create();

}
