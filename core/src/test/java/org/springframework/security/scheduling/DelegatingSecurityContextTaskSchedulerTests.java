/*
 * Copyright 2002-2021 the original author or authors.
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

import java.time.Instant;
import java.util.Date;
import java.util.concurrent.ScheduledFuture;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.Trigger;
import org.springframework.scheduling.concurrent.ConcurrentTaskScheduler;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.BDDMockito.willAnswer;
import static org.mockito.Mockito.verify;

/**
 * Test An implementation of {@link TaskScheduler} invoking it whenever the trigger
 * indicates a next execution time.
 *
 * @author Richard Valdivieso
 * @since 5.1
 */
public class DelegatingSecurityContextTaskSchedulerTests {

	@Mock
	private TaskScheduler scheduler;

	@Mock
	private SecurityContext securityContext;

	@Mock
	private Runnable runnable;

	@Mock
	private Trigger trigger;

	private SecurityContext originalSecurityContext;

	private DelegatingSecurityContextTaskScheduler delegatingSecurityContextTaskScheduler;

	@BeforeEach
	public void setup() {
		MockitoAnnotations.initMocks(this);
		this.originalSecurityContext = SecurityContextHolder.createEmptyContext();
		this.delegatingSecurityContextTaskScheduler = new DelegatingSecurityContextTaskScheduler(this.scheduler,
				this.securityContext);
	}

	@AfterEach
	public void cleanup() {
		SecurityContextHolder.clearContext();
		this.delegatingSecurityContextTaskScheduler = null;
	}

	@Test
	public void constructorWhenNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new DelegatingSecurityContextTaskScheduler(null));
	}

	@Test
	public void scheduleWhenDefaultThenCurrentSecurityContextPropagated() throws Exception {
		willAnswer((invocation) -> {
			assertThat(SecurityContextHolder.getContext()).isEqualTo(this.originalSecurityContext);
			return null;
		}).given(this.runnable).run();
		TaskScheduler delegateTaskScheduler = new ConcurrentTaskScheduler();
		this.delegatingSecurityContextTaskScheduler = new DelegatingSecurityContextTaskScheduler(delegateTaskScheduler);
		assertWrapped(this.runnable);
	}

	@Test
	public void scheduleWhenSecurityContextThenSecurityContextPropagated() throws Exception {
		willAnswer((invocation) -> {
			assertThat(SecurityContextHolder.getContext()).isEqualTo(this.securityContext);
			return null;
		}).given(this.runnable).run();
		TaskScheduler delegateTaskScheduler = new ConcurrentTaskScheduler();
		this.delegatingSecurityContextTaskScheduler = new DelegatingSecurityContextTaskScheduler(delegateTaskScheduler,
				this.securityContext);
		assertWrapped(this.runnable);
	}

	private void assertWrapped(Runnable runnable) throws Exception {
		ScheduledFuture<?> schedule = this.delegatingSecurityContextTaskScheduler.schedule(runnable, new Date());
		schedule.get();
		verify(this.runnable).run();
		assertThat(SecurityContextHolder.getContext()).isEqualTo(this.originalSecurityContext);
	}

	@Test
	public void scheduleWhenRunnableTriggerThenDelegates() {
		this.delegatingSecurityContextTaskScheduler.schedule(this.runnable, this.trigger);
		verify(this.scheduler).schedule(any(Runnable.class), any(Trigger.class));
	}

	@Test
	public void scheduleWhenRunnableDateThenDelegates() {
		Instant date = Instant.now();
		this.delegatingSecurityContextTaskScheduler.schedule(this.runnable, date);
		verify(this.scheduler).schedule(any(Runnable.class), any(Instant.class));
	}

	@Test
	public void scheduleAtFixedRateWhenRunnableDateLongThenDelegates() {
		Date date = new Date(1544751374L);
		this.delegatingSecurityContextTaskScheduler.scheduleAtFixedRate(this.runnable, date, 1000L);
		verify(this.scheduler).scheduleAtFixedRate(isA(Runnable.class), isA(Date.class), eq(1000L));
	}

	@Test
	public void scheduleAtFixedRateWhenRunnableLongThenDelegates() {
		this.delegatingSecurityContextTaskScheduler.scheduleAtFixedRate(this.runnable, 1000L);
		verify(this.scheduler).scheduleAtFixedRate(isA(Runnable.class), eq(1000L));
	}

}
