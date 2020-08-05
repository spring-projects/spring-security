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

import static org.mockito.ArgumentMatchers.eq;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.spy;

import java.util.concurrent.Callable;

import org.junit.After;
import org.junit.Before;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Abstract base class for testing classes that extend
 * {@link AbstractDelegatingSecurityContextSupport}
 *
 * @author Rob Winch
 * @since 3.2
 *
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ DelegatingSecurityContextRunnable.class, DelegatingSecurityContextCallable.class })
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

	public final void explicitSecurityContextPowermockSetup() throws Exception {
		spy(DelegatingSecurityContextCallable.class);
		doReturn(wrappedCallable).when(DelegatingSecurityContextCallable.class, "create", eq(callable),
				securityContextCaptor.capture());
		spy(DelegatingSecurityContextRunnable.class);
		doReturn(wrappedRunnable).when(DelegatingSecurityContextRunnable.class, "create", eq(runnable),
				securityContextCaptor.capture());
	}

	public final void currentSecurityContextPowermockSetup() throws Exception {
		spy(DelegatingSecurityContextCallable.class);
		doReturn(wrappedCallable).when(DelegatingSecurityContextCallable.class, "create", callable, null);
		spy(DelegatingSecurityContextRunnable.class);
		doReturn(wrappedRunnable).when(DelegatingSecurityContextRunnable.class, "create", runnable, null);
	}

	@Before
	public final void setContext() {
		SecurityContextHolder.setContext(currentSecurityContext);
	}

	@After
	public final void clearContext() {
		SecurityContextHolder.clearContext();
	}

}
