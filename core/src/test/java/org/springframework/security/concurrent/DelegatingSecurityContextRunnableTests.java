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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.stubbing.Answer;

import org.springframework.core.task.SyncTaskExecutor;
import org.springframework.core.task.support.ExecutorServiceAdapter;
import org.springframework.security.core.context.MockSecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.willAnswer;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 * @since 3.2
 */
@ExtendWith(MockitoExtension.class)
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

	@BeforeEach
	public void setUp() {
		this.originalSecurityContext = SecurityContextHolder.createEmptyContext();
		this.executor = Executors.newFixedThreadPool(1);
	}

	private void givenDelegateRunWillAnswerWithCurrentSecurityContext() {
		willAnswer((Answer<Object>) (invocation) -> {
			assertThat(SecurityContextHolder.getContext()).isEqualTo(this.securityContext);
			return null;
		}).given(this.delegate).run();
	}

	private void givenDelegateRunWillAnswerWithCurrentSecurityContext(SecurityContextHolderStrategy strategy) {
		willAnswer((Answer<Object>) (invocation) -> {
			assertThat(strategy.getContext()).isEqualTo(this.securityContext);
			return null;
		}).given(this.delegate).run();
	}

	@AfterEach
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void constructorNullDelegate() {
		assertThatIllegalArgumentException().isThrownBy(() -> new DelegatingSecurityContextRunnable(null));
	}

	@Test
	public void constructorNullDelegateNonNullSecurityContext() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new DelegatingSecurityContextRunnable(null, this.securityContext));
	}

	@Test
	public void constructorNullDelegateAndSecurityContext() {
		assertThatIllegalArgumentException().isThrownBy(() -> new DelegatingSecurityContextRunnable(null, null));
	}

	@Test
	public void constructorNullSecurityContext() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new DelegatingSecurityContextRunnable(this.delegate, null));
	}

	@Test
	public void call() throws Exception {
		givenDelegateRunWillAnswerWithCurrentSecurityContext();
		this.runnable = new DelegatingSecurityContextRunnable(this.delegate, this.securityContext);
		assertWrapped(this.runnable);
	}

	@Test
	public void callDefaultSecurityContext() throws Exception {
		givenDelegateRunWillAnswerWithCurrentSecurityContext();
		SecurityContextHolder.setContext(this.securityContext);
		this.runnable = new DelegatingSecurityContextRunnable(this.delegate);
		SecurityContextHolder.clearContext(); // ensure runnable is what sets up the
												// SecurityContextHolder
		assertWrapped(this.runnable);
	}

	@Test
	public void callDefaultSecurityContextWithCustomSecurityContextHolderStrategy() throws Exception {
		SecurityContextHolderStrategy securityContextHolderStrategy = spy(new MockSecurityContextHolderStrategy());
		givenDelegateRunWillAnswerWithCurrentSecurityContext(securityContextHolderStrategy);
		securityContextHolderStrategy.setContext(this.securityContext);
		DelegatingSecurityContextRunnable runnable = new DelegatingSecurityContextRunnable(this.delegate);
		runnable.setSecurityContextHolderStrategy(securityContextHolderStrategy);
		this.runnable = runnable;
		// ensure callable is what sets up the SecurityContextHolder
		securityContextHolderStrategy.clearContext();
		assertWrapped(this.runnable);
		verify(securityContextHolderStrategy, atLeastOnce()).getContext();
	}

	// SEC-3031
	@Test
	public void callOnSameThread() throws Exception {
		givenDelegateRunWillAnswerWithCurrentSecurityContext();
		this.originalSecurityContext = this.securityContext;
		SecurityContextHolder.setContext(this.originalSecurityContext);
		this.executor = synchronousExecutor();
		this.runnable = new DelegatingSecurityContextRunnable(this.delegate, this.securityContext);
		assertWrapped(this.runnable);
	}

	@Test
	public void createNullDelegate() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> DelegatingSecurityContextRunnable.create(null, this.securityContext));
	}

	@Test
	public void createNullDelegateAndSecurityContext() {
		assertThatIllegalArgumentException().isThrownBy(() -> DelegatingSecurityContextRunnable.create(null, null));
	}

	@Test
	public void createNullSecurityContext() throws Exception {
		givenDelegateRunWillAnswerWithCurrentSecurityContext();
		SecurityContextHolder.setContext(this.securityContext);
		this.runnable = DelegatingSecurityContextRunnable.create(this.delegate, null);
		SecurityContextHolder.clearContext(); // ensure runnable is what sets up the
												// SecurityContextHolder
		assertWrapped(this.runnable);
	}

	@Test
	public void create() throws Exception {
		givenDelegateRunWillAnswerWithCurrentSecurityContext();
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
