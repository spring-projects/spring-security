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
package org.springframework.security.task;

import static org.mockito.Mockito.verify;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.springframework.core.task.AsyncTaskExecutor;
import org.springframework.security.concurrent.AbstractDelegatingSecurityContextExecutorTests;

/**
 * Abstract class for testing {@link DelegatingSecurityContextAsyncTaskExecutor} which
 * allows customization of how {@link DelegatingSecurityContextAsyncTaskExecutor} and its
 * mocks are created.
 *
 * @author Rob Winch
 * @since 3.2
 * @see CurrentDelegatingSecurityContextAsyncTaskExecutorTests
 * @see ExplicitDelegatingSecurityContextAsyncTaskExecutorTests
 */
public abstract class AbstractDelegatingSecurityContextAsyncTaskExecutorTests extends
		AbstractDelegatingSecurityContextExecutorTests {
	@Mock
	protected AsyncTaskExecutor taskExecutorDelegate;

	private DelegatingSecurityContextAsyncTaskExecutor executor;

	@Before
	public final void setUpExecutor() {
		executor = create();
	}

	@Test
	public void executeStartTimeout() {
		executor.execute(runnable, 1);
		verify(getExecutor()).execute(wrappedRunnable, 1);
	}

	@Test
	public void submit() {
		executor.submit(runnable);
		verify(getExecutor()).submit(wrappedRunnable);
	}

	@Test
	public void submitCallable() {
		executor.submit(callable);
		verify(getExecutor()).submit(wrappedCallable);
	}

	protected AsyncTaskExecutor getExecutor() {
		return taskExecutorDelegate;
	}

	protected abstract DelegatingSecurityContextAsyncTaskExecutor create();
}
