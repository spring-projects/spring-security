/*
 * Copyright 2004-present the original author or authors.
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
import java.util.function.UnaryOperator;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.stubbing.OngoingStubbing;

import org.springframework.security.core.context.SecurityContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 * @since 3.2
 *
 */
public class DelegatingSecurityContextSupportTests extends AbstractDelegatingSecurityContextTestSupport {

	private AbstractDelegatingSecurityContextSupport support;

	@Mock
	private UnaryOperator<Runnable> runnableWrapper;

	@Mock
	private UnaryOperator<Callable<?>> callableWrapper;

	@Test
	public void wrapCallable() throws Exception {
		explicitSecurityContextSetup();
		this.support = new ConcreteDelegatingSecurityContextSupport(this.securityContext);
		assertThat(this.support.wrap(this.callable)).isSameAs(this.wrappedCallable);
		assertThat(this.securityContextCaptor.getValue()).isSameAs(this.securityContext);
	}

	@Test
	public void wrapCallableNullSecurityContext() throws Exception {
		currentSecurityContextSetup();
		this.support = new ConcreteDelegatingSecurityContextSupport(null);
		assertThat(this.support.wrap(this.callable)).isSameAs(this.wrappedCallable);
	}

	@Test
	public void wrapRunnable() throws Exception {
		explicitSecurityContextSetup();
		this.support = new ConcreteDelegatingSecurityContextSupport(this.securityContext);
		assertThat(this.support.wrap(this.runnable)).isSameAs(this.wrappedRunnable);
		assertThat(this.securityContextCaptor.getValue()).isSameAs(this.securityContext);
	}

	@Test
	public void wrapRunnableNullSecurityContext() throws Exception {
		currentSecurityContextSetup();
		this.support = new ConcreteDelegatingSecurityContextSupport(null);
		assertThat(this.support.wrap(this.runnable)).isSameAs(this.wrappedRunnable);
	}

	@Test
	public void setRunnableWrapper() throws Exception {
		this.support = new ConcreteDelegatingSecurityContextSupport(this.securityContext);
		this.support.setRunnableWrapper(this.runnableWrapper);
		Mockito.when(this.runnableWrapper.apply(this.runnable)).thenReturn(this.wrappedRunnable);
		assertThat(this.support.wrap(this.runnable)).isSameAs(this.wrappedRunnable);
		ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);
		verify(this.runnableWrapper).apply(runnableCaptor.capture());
		assertThat(runnableCaptor.getValue()).isSameAs(this.runnable);
	}

	@Test
	public void setCallableWrapper() throws Exception {
		this.support = new ConcreteDelegatingSecurityContextSupport(this.securityContext);
		this.support.setCallableWrapper(this.callableWrapper);
		OngoingStubbing<Callable<?>> stubbing = Mockito.when(this.callableWrapper.apply(this.callable));
		stubbing.thenReturn(this.wrappedCallable);
		assertThat(this.support.wrap(this.callable)).isSameAs(this.wrappedCallable);
		ArgumentCaptor<Callable<?>> callableCaptor = ArgumentCaptor.forClass(Callable.class);
		verify(this.callableWrapper).apply(callableCaptor.capture());
		assertThat(callableCaptor.getValue()).isSameAs(this.callable);
	}

	private static class ConcreteDelegatingSecurityContextSupport extends AbstractDelegatingSecurityContextSupport {

		ConcreteDelegatingSecurityContextSupport(SecurityContext securityContext) {
			super(securityContext);
		}

	}

}
