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

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.core.task.support.ContextPropagatingTaskDecorator;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link SecurityContextHolderThreadLocalAccessor}.
 *
 * @author Steve Riesenberg
 * @author Tadaya Tsuyukubo
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
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		securityContext.setAuthentication(authentication);
		this.threadLocalAccessor.setValue(securityContext);
		assertThat(SecurityContextHolder.getContext()).isNotSameAs(securityContext);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(authentication);
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

	@Test
	public void newSecurityContextInDifferentThread() throws Exception {
		Authentication authA = new TestingAuthenticationToken("foo", "password");
		Authentication authB = new TestingAuthenticationToken("bar", "password");

		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(authA);
		SecurityContextHolder.setContext(securityContext);

		CountDownLatch latch = new CountDownLatch(1);
		AtomicReference<SecurityContext> contextHolder = new AtomicReference<>();
		AtomicReference<Authentication> authHolder = new AtomicReference<>();
		Runnable runnable = () -> {
			SecurityContext context = SecurityContextHolder.getContext();
			contextHolder.set(context);
			authHolder.set(context.getAuthentication());
			context.setAuthentication(authB);
			latch.countDown();
		};

		ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
		executor.setTaskDecorator(new ContextPropagatingTaskDecorator());
		executor.afterPropertiesSet();

		executor.execute(runnable);

		boolean finished = latch.await(10, TimeUnit.SECONDS);
		assertThat(finished).isTrue();

		assertThat(contextHolder.get()).isNotSameAs(securityContext);
		assertThat(authHolder.get()).isSameAs(authA);

		SecurityContext current = SecurityContextHolder.getContext();
		assertThat(current).isSameAs(securityContext);
		assertThat(current.getAuthentication()).isSameAs(authA);
	}

}
