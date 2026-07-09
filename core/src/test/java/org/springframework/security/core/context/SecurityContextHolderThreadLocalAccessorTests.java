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

import java.util.concurrent.atomic.AtomicInteger;

import io.micrometer.context.ContextSnapshot;
import io.micrometer.context.ContextSnapshotFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.util.context.Context;

import org.springframework.security.authentication.TestingAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

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
	public void getValueWhenSecurityContextHolderSetThenReturnsSecurityContext() {
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(new TestingAuthenticationToken("user", "password"));
		SecurityContextHolder.setContext(securityContext);
		assertThat(this.threadLocalAccessor.getValue()).isSameAs(securityContext);
	}

	@Test
	public void setValueWhenSecurityContextThenSetsSecurityContextHolder() {
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(new TestingAuthenticationToken("user", "password"));
		this.threadLocalAccessor.setValue(securityContext);
		assertThat(SecurityContextHolder.getContext()).isSameAs(securityContext);
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

		ContextSnapshotFactory factory = ContextSnapshotFactory.builder().clearMissing(true).build();
		try (ContextSnapshot.Scope scope = factory.setThreadLocalsFrom(Context.empty())) {
			assertThat(invocationCount.get()).as("entering the scope must not invoke the deferred supplier").isZero();
		}

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

}
