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

package org.springframework.security.scheduling;

import org.junit.jupiter.api.Test;
import org.mockito.Mock;

import org.springframework.scheduling.SchedulingTaskExecutor;
import org.springframework.security.task.AbstractDelegatingSecurityContextAsyncTaskExecutorTests;

import static org.mockito.Mockito.verify;

/**
 * Abstract class for testing {@link DelegatingSecurityContextSchedulingTaskExecutor}
 * which allows customization of how
 * {@link DelegatingSecurityContextSchedulingTaskExecutor} and its mocks are created.
 *
 * @author Rob Winch
 * @since 3.2
 * @see CurrentSecurityContextSchedulingTaskExecutorTests
 * @see ExplicitSecurityContextSchedulingTaskExecutorTests
 */
public abstract class AbstractSecurityContextSchedulingTaskExecutorTests
		extends AbstractDelegatingSecurityContextAsyncTaskExecutorTests {

	@Mock
	protected SchedulingTaskExecutor taskExecutorDelegate;

	private DelegatingSecurityContextSchedulingTaskExecutor executor;

	@Test
	public void prefersShortLivedTasks() {
		this.executor = create();
		this.executor.prefersShortLivedTasks();
		verify(this.taskExecutorDelegate).prefersShortLivedTasks();
	}

	@Override
	protected SchedulingTaskExecutor getExecutor() {
		return this.taskExecutorDelegate;
	}

	@Override
	protected abstract DelegatingSecurityContextSchedulingTaskExecutor create();

}
