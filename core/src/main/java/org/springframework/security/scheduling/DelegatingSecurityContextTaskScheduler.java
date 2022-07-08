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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.ScheduledFuture;

import org.springframework.core.task.TaskExecutor;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.Trigger;
import org.springframework.security.concurrent.DelegatingSecurityContextRunnable;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

/**
 * An implementation of {@link TaskScheduler} invoking it whenever the trigger indicates a
 * next execution time.
 *
 * @author Richard Valdivieso
 * @since 5.1
 */
public class DelegatingSecurityContextTaskScheduler implements TaskScheduler {

	private final TaskScheduler delegate;

	private final SecurityContext securityContext;

	/**
	 * Creates a new {@link DelegatingSecurityContextTaskScheduler} that uses the
	 * specified {@link SecurityContext}.
	 * @param delegateTaskScheduler the {@link TaskScheduler} to delegate to. Cannot be
	 * null.
	 * @param securityContext the {@link SecurityContext} to use for each
	 * {@link DelegatingSecurityContextRunnable} or null to default to the current
	 * {@link SecurityContext}
	 * @since 5.6
	 */
	public DelegatingSecurityContextTaskScheduler(TaskScheduler delegateTaskScheduler,
			SecurityContext securityContext) {
		Assert.notNull(delegateTaskScheduler, "delegateTaskScheduler cannot be null");
		this.delegate = delegateTaskScheduler;
		this.securityContext = securityContext;
	}

	/**
	 * Creates a new {@link DelegatingSecurityContextTaskScheduler} that uses the current
	 * {@link SecurityContext} from the {@link SecurityContextHolder}.
	 * @param delegate the {@link TaskExecutor} to delegate to. Cannot be null.
	 */
	public DelegatingSecurityContextTaskScheduler(TaskScheduler delegate) {
		this(delegate, null);
	}

	@Override
	public ScheduledFuture<?> schedule(Runnable task, Trigger trigger) {
		return this.delegate.schedule(wrap(task), trigger);
	}

	@Override
	public ScheduledFuture<?> schedule(Runnable task, Date startTime) {
		return this.delegate.schedule(wrap(task), startTime);
	}

	@Override
	public ScheduledFuture<?> scheduleAtFixedRate(Runnable task, Date startTime, long period) {
		return this.delegate.scheduleAtFixedRate(wrap(task), startTime, period);
	}

	@Override
	public ScheduledFuture<?> scheduleAtFixedRate(Runnable task, long period) {
		return this.delegate.scheduleAtFixedRate(wrap(task), period);
	}

	@Override
	public ScheduledFuture<?> scheduleWithFixedDelay(Runnable task, Date startTime, long delay) {
		return this.delegate.scheduleWithFixedDelay(wrap(task), startTime, delay);
	}

	@Override
	public ScheduledFuture<?> scheduleWithFixedDelay(Runnable task, long delay) {
		return this.delegate.scheduleWithFixedDelay(wrap(task), delay);
	}

	@Override
	public ScheduledFuture<?> schedule(Runnable task, Instant startTime) {
		return this.delegate.schedule(wrap(task), startTime);
	}

	@Override
	public ScheduledFuture<?> scheduleAtFixedRate(Runnable task, Instant startTime, Duration period) {
		return this.delegate.scheduleAtFixedRate(wrap(task), startTime, period);
	}

	@Override
	public ScheduledFuture<?> scheduleAtFixedRate(Runnable task, Duration period) {
		return this.delegate.scheduleAtFixedRate(wrap(task), period);
	}

	@Override
	public ScheduledFuture<?> scheduleWithFixedDelay(Runnable task, Instant startTime, Duration delay) {
		return this.delegate.scheduleWithFixedDelay(wrap(task), startTime, delay);
	}

	@Override
	public ScheduledFuture<?> scheduleWithFixedDelay(Runnable task, Duration delay) {
		return this.delegate.scheduleWithFixedDelay(wrap(task), delay);
	}

	@Override
	public Clock getClock() {
		return this.delegate.getClock();
	}

	private Runnable wrap(Runnable delegate) {
		return DelegatingSecurityContextRunnable.create(delegate, this.securityContext);
	}

}
