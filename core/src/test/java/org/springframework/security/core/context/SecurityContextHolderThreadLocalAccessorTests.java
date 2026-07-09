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

package org.springframework.security.core.context;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import io.micrometer.context.ContextExecutorService;
import io.micrometer.context.ContextSnapshot;
import io.micrometer.context.ContextSnapshotFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.util.context.Context;

import org.springframework.security.authentication.TestingAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link SecurityContextHolderThreadLocalAccessor}.
 *
 * @author Steve Riesenberg
 */
public class SecurityContextHolderThreadLocalAccessorTests {

	private SecurityContextHolderThreadLocalAccessor threadLocalAccessor;

	@BeforeEach
	public void setUp() {
		this.threadLocalAccessor = new SecurityContextHolderThreadLocalAccessor();
	}

	@AfterEach
	public void tearDown() {
		this.threadLocalAccessor.setValue();
	}

	@Test
	public void keyAlwaysReturnsSecurityContextClassName() {
		assertThat(this.threadLocalAccessor.key()).isEqualTo(SecurityContext.class.getName());
	}

	@Test
	public void getValueWhenSecurityContextHolderNotSetThenReturnsNull() {
		assertThat(this.threadLocalAccessor.getValue()).isNull();
	}

	@Test
	public void getValueWhenSecurityContextHolderSetThenReturnsSupplierOfSecurityContext() {
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(new TestingAuthenticationToken("user", "password"));
		SecurityContextHolder.setContext(securityContext);
		Supplier<SecurityContext> deferred = this.threadLocalAccessor.getValue();
		assertThat(deferred).isNotNull();
		assertThat(deferred.get()).isSameAs(securityContext);
	}

	// gh-18059
	@Test
	public void getValueWhenContextAutoCreatedThenReturnsNull() {
		SecurityContextHolder.getContext();
		assertThat(this.threadLocalAccessor.getValue()).isNull();
	}

	// gh-18059
	@Test
	public void getValueWhenEmptyContextSetThenReturnsNull() {
		SecurityContextHolder.setContext(SecurityContextHolder.createEmptyContext());
		assertThat(this.threadLocalAccessor.getValue()).isNull();
	}

	// gh-18059
	@Test
	public void getValueWhenAutoCreatedContextModifiedThenReturnsSupplier() {
		SecurityContext securityContext = SecurityContextHolder.getContext();
		securityContext.setAuthentication(new TestingAuthenticationToken("user", "password"));
		Supplier<SecurityContext> deferred = this.threadLocalAccessor.getValue();
		assertThat(deferred).isNotNull();
		assertThat(deferred.get()).isSameAs(securityContext);
	}

	// gh-18059
	@Test
	@SuppressWarnings("unchecked")
	public void getValueWhenDeferredContextSetThenDoesNotInvokeSupplier() {
		Supplier<SecurityContext> deferredContext = mock(Supplier.class);
		SecurityContextHolder.setDeferredContext(deferredContext);
		Supplier<SecurityContext> result = this.threadLocalAccessor.getValue();
		assertThat(result).isNotNull();
		verifyNoInteractions(deferredContext);
	}

	@Test
	public void setValueWhenSupplierThenSetsSecurityContextHolder() {
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(new TestingAuthenticationToken("user", "password"));
		this.threadLocalAccessor.setValue(() -> securityContext);
		assertThat(SecurityContextHolder.getContext()).isSameAs(securityContext);
	}

	// gh-18059
	@Test
	@SuppressWarnings("unchecked")
	public void setValueWhenSupplierThenDoesNotInvokeSupplier() {
		Supplier<SecurityContext> deferredContext = mock(Supplier.class);
		this.threadLocalAccessor.setValue(deferredContext);
		verifyNoInteractions(deferredContext);
	}

	@Test
	public void setValueWhenNullThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.threadLocalAccessor.setValue(null))
			.withMessage("securityContext cannot be null");
		// @formatter:on
	}

	@Test
	public void setValueWhenSecurityContextSetThenClearsSecurityContextHolder() {
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(new TestingAuthenticationToken("user", "password"));
		SecurityContextHolder.setContext(securityContext);
		this.threadLocalAccessor.setValue();

		SecurityContext emptyContext = SecurityContextHolder.createEmptyContext();
		assertThat(SecurityContextHolder.getContext()).isEqualTo(emptyContext);
	}

	// gh-18059
	@Test
	public void captureAllWhenDeferredContextSetThenDoesNotInvokeSupplier() {
		SecurityContext securityContext = new SecurityContextImpl(new TestingAuthenticationToken("user", "password"));
		AtomicInteger invocationCount = new AtomicInteger();
		SecurityContextHolder.setDeferredContext(() -> {
			invocationCount.incrementAndGet();
			return securityContext;
		});

		ContextSnapshotFactory factory = ContextSnapshotFactory.builder().build();
		factory.captureAll();

		assertThat(invocationCount.get()).as("snapshot capture must not invoke the deferred supplier").isZero();
	}

	// gh-18059
	@Test
	public void setThreadLocalsFromWhenContextMissingKeyThenDoesNotInvokeSupplier() {
		// The branch from the issue's stack trace: clearMissing=true and no
		// SecurityContext key in the Reactor Context invokes accessor.getValue()
		// to save the previous value before clearing.
		SecurityContext securityContext = new SecurityContextImpl(new TestingAuthenticationToken("user", "password"));
		AtomicInteger invocationCount = new AtomicInteger();
		SecurityContextHolder.setDeferredContext(() -> {
			invocationCount.incrementAndGet();
			return securityContext;
		});
		Supplier<SecurityContext> before = this.threadLocalAccessor.getValue();

		ContextSnapshotFactory factory = ContextSnapshotFactory.builder().clearMissing(true).build();
		try (ContextSnapshot.Scope scope = factory.setThreadLocalsFrom(Context.empty())) {
			assertThat(this.threadLocalAccessor.getValue()).as("cleared inside the scope").isNull();
		}

		assertThat(this.threadLocalAccessor.getValue()).as("restored on scope close, not re-wrapped").isSameAs(before);
		assertThat(invocationCount.get()).as("leaving the scope must not invoke the deferred supplier").isZero();
	}

	// gh-18059
	@Test
	public void captureAllWhenDeferredContextReentersPropagationThenDoesNotRecurse() {
		// Models the issue's Lettuce/Redis flow: materializing the deferred context
		// itself triggers Mono.subscribe -> context propagation -> accessor.getValue().
		// Bounded so a regression fails the assertion instead of a StackOverflowError.
		SecurityContext securityContext = new SecurityContextImpl(new TestingAuthenticationToken("user", "password"));
		ContextSnapshotFactory factory = ContextSnapshotFactory.builder().build();
		AtomicInteger invocationCount = new AtomicInteger();
		SecurityContextHolder.setDeferredContext(() -> {
			if (invocationCount.incrementAndGet() <= 3) {
				factory.captureAll();
			}
			return securityContext;
		});

		factory.captureAll();

		assertThat(invocationCount.get()).as("snapshot capture must not invoke the deferred supplier, even reentrantly")
			.isZero();
	}

	// gh-18059
	@Test
	public void getValueWhenDeferredContextReentersAccessorThenDoesNotRecurseAndReturnsCallableSupplier() {
		SecurityContext securityContext = new SecurityContextImpl(new TestingAuthenticationToken("user", "password"));
		AtomicInteger invocationCount = new AtomicInteger();
		Supplier<SecurityContext> reentrantSupplier = () -> {
			// Bound recursion so a regression fails the assertion instead of
			// crashing the JVM with StackOverflowError.
			if (invocationCount.incrementAndGet() > 1) {
				return securityContext;
			}
			Supplier<SecurityContext> nested = this.threadLocalAccessor.getValue();
			if (nested != null) {
				nested.get();
			}
			return securityContext;
		};
		SecurityContextHolder.setDeferredContext(reentrantSupplier);

		Supplier<SecurityContext> result = this.threadLocalAccessor.getValue();

		assertThat(result).isNotNull();
		assertThat(invocationCount.get()).isZero();
		assertThat(result.get()).isSameAs(securityContext);
	}

	// gh-18059
	@Test
	public void contextPropagationToWorkerThreadDoesNotMaterializeDeferredSupplier()
			throws ExecutionException, InterruptedException, TimeoutException {
		// Cross-thread propagation via ContextExecutorService: micrometer captures on
		// submit() and applies the snapshot on the worker thread.
		SecurityContext securityContext = new SecurityContextImpl(new TestingAuthenticationToken("user", "password"));
		AtomicInteger invocationCount = new AtomicInteger();
		Supplier<SecurityContext> deferredSupplier = () -> {
			invocationCount.incrementAndGet();
			return securityContext;
		};

		ExecutorService raw = Executors.newSingleThreadExecutor();
		ContextSnapshotFactory factory = ContextSnapshotFactory.builder().build();
		ExecutorService propagating = ContextExecutorService.wrap(raw, factory);
		try {
			assertThat(raw.submit(this.threadLocalAccessor::getValue).get(5, TimeUnit.SECONDS))
				.as("worker thread initially has no SecurityContext")
				.isNull();

			SecurityContextHolder.setDeferredContext(deferredSupplier);
			Supplier<SecurityContext> captured = this.threadLocalAccessor.getValue();

			AtomicInteger invocationsAtTaskStart = new AtomicInteger(-1);
			AtomicReference<Supplier<SecurityContext>> workerSupplier = new AtomicReference<>();
			AtomicReference<SecurityContext> workerContext = new AtomicReference<>();
			AtomicInteger invocationsAfterMaterialization = new AtomicInteger(-1);

			propagating.submit(() -> {
				invocationsAtTaskStart.set(invocationCount.get());
				workerSupplier.set(this.threadLocalAccessor.getValue());
				workerContext.set(SecurityContextHolder.getContext());
				invocationsAfterMaterialization.set(invocationCount.get());
			}).get(5, TimeUnit.SECONDS);

			assertThat(invocationsAtTaskStart.get())
				.as("micrometer's capture+apply path must not invoke the deferred supplier")
				.isZero();
			assertThat(workerSupplier.get())
				.as("worker thread receives the same supplier instance captured on the submitter")
				.isSameAs(captured);
			assertThat(workerContext.get())
				.as("SecurityContextHolder.getContext() on the worker materializes the supplier")
				.isSameAs(securityContext);
			assertThat(invocationsAfterMaterialization.get())
				.as("materialization on the worker invokes the supplier exactly once")
				.isOne();

			// Probe via the unwrapped executor so this submission does not propagate.
			assertThat(raw.submit(this.threadLocalAccessor::getValue).get(5, TimeUnit.SECONDS))
				.as("worker thread's prior (empty) state must be restored after the task")
				.isNull();
		}
		finally {
			propagating.shutdown();
			raw.shutdownNow();
		}
	}

}
