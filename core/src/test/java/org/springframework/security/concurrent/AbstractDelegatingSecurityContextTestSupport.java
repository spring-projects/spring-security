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

import org.junit.After;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.mockito.ArgumentMatchers.eq;

/**
 * Abstract base class for testing classes that extend
 * {@link AbstractDelegatingSecurityContextSupport}
 *
 * @author Rob Winch
 * @since 3.2
 *
 */
@RunWith(MockitoJUnitRunner.class)
public abstract class AbstractDelegatingSecurityContextTestSupport {

	@Mock
	protected SecurityContext securityContext;

	@Mock
	protected SecurityContext currentSecurityContext;

	@Captor
	protected ArgumentCaptor<SecurityContext> securityContextCaptor;

	@Mock
	protected Callable<Object> callable;

	@Mock
	protected Callable<Object> wrappedCallable;

	@Mock
	protected Runnable runnable;

	@Mock
	protected Runnable wrappedRunnable;

	@Mock
	protected MockedStatic<DelegatingSecurityContextCallable> delegatingSecurityContextCallable;

	@Mock
	protected MockedStatic<DelegatingSecurityContextRunnable> delegatingSecurityContextRunnable;

	public final void explicitSecurityContextSetup() throws Exception {
		this.delegatingSecurityContextCallable.when(
				() -> DelegatingSecurityContextCallable.create(eq(this.callable), this.securityContextCaptor.capture()))
				.thenReturn(this.wrappedCallable);
		this.delegatingSecurityContextRunnable.when(
				() -> DelegatingSecurityContextRunnable.create(eq(this.runnable), this.securityContextCaptor.capture()))
				.thenReturn(this.wrappedRunnable);
	}

	public final void currentSecurityContextSetup() throws Exception {
		this.delegatingSecurityContextCallable.when(() -> DelegatingSecurityContextCallable.create(this.callable, null))
				.thenReturn(this.wrappedCallable);
		this.delegatingSecurityContextRunnable.when(() -> DelegatingSecurityContextRunnable.create(this.runnable, null))
				.thenReturn(this.wrappedRunnable);
	}

	@Before
	public final void setContext() {
		SecurityContextHolder.setContext(this.currentSecurityContext);
	}

	@After
	public final void clearContext() {
		SecurityContextHolder.clearContext();
	}

}
