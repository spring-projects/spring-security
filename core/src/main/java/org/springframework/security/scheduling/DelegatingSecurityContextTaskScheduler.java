/*
 * Copyright 2002-2018 the original author or authors.
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

import java.util.Date;
import java.util.concurrent.ScheduledFuture;

import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.Trigger;
import org.springframework.util.Assert;

/**
 * An implementation of {@link TaskScheduler} invoking it whenever the trigger indicates a
 * next execution time.
 *
 * @author Richard Valdivieso
 * @since 5.1
 */
public class DelegatingSecurityContextTaskScheduler implements TaskScheduler {

	private final TaskScheduler taskScheduler;

	/**
	 * Creates a new {@link DelegatingSecurityContextTaskScheduler}
	 * @param taskScheduler the {@link TaskScheduler}
	 */
	public DelegatingSecurityContextTaskScheduler(TaskScheduler taskScheduler) {
		Assert.notNull(taskScheduler, "Task scheduler must not be null");
		this.taskScheduler = taskScheduler;
	}

	@Override
	public ScheduledFuture<?> schedule(Runnable task, Trigger trigger) {
		return this.taskScheduler.schedule(task, trigger);
	}

	@Override
	public ScheduledFuture<?> schedule(Runnable task, Date startTime) {
		return this.taskScheduler.schedule(task, startTime);
	}

	@Override
	public ScheduledFuture<?> scheduleAtFixedRate(Runnable task, Date startTime, long period) {
		return this.taskScheduler.scheduleAtFixedRate(task, startTime, period);
	}

	@Override
	public ScheduledFuture<?> scheduleAtFixedRate(Runnable task, long period) {
		return this.taskScheduler.scheduleAtFixedRate(task, period);
	}

	@Override
	public ScheduledFuture<?> scheduleWithFixedDelay(Runnable task, Date startTime, long delay) {
		return this.taskScheduler.scheduleWithFixedDelay(task, startTime, delay);
	}

	@Override
	public ScheduledFuture<?> scheduleWithFixedDelay(Runnable task, long delay) {
		return this.taskScheduler.scheduleWithFixedDelay(task, delay);
	}

}
