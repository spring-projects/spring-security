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

import java.util.concurrent.Executor;

import org.junit.Before;
import org.mockito.Mock;

import org.springframework.core.task.TaskExecutor;
import org.springframework.security.concurrent.AbstractDelegatingSecurityContextExecutorTests;
import org.springframework.security.concurrent.DelegatingSecurityContextExecutor;
import org.springframework.security.core.context.SecurityContext;

/**
 * Tests using the current {@link SecurityContext} on
 * {@link DelegatingSecurityContextExecutor}
 *
 * @author Rob Winch
 * @since 3.2
 *
 */
public class CurrentDelegatingSecurityContextTaskExecutorTests extends AbstractDelegatingSecurityContextExecutorTests {

	@Mock
	private TaskExecutor taskExecutorDelegate;

	@Before
	public void setUp() throws Exception {
		currentSecurityContextPowermockSetup();
	}

	protected Executor getExecutor() {
		return taskExecutorDelegate;
	}

	protected DelegatingSecurityContextExecutor create() {
		return new DelegatingSecurityContextTaskExecutor(taskExecutorDelegate);
	}

}
