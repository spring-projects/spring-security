/*
 * Copyright 2020-2023 the original author or authors.
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

import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnJre;
import org.junit.jupiter.api.condition.JRE;

import org.springframework.core.task.VirtualThreadTaskExecutor;
import org.springframework.scheduling.concurrent.ConcurrentTaskScheduler;
import org.springframework.scheduling.support.PeriodicTrigger;
import org.springframework.security.DelegatingSecurityContextTestUtils;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Steve Riesenberg
 */
public class DelegatingSecurityContextTaskSchedulerIntegrationTests {

	@Test
	public void scheduleWhenThreadFactoryIsPlatformThenSecurityContextPropagated() throws Exception {
		SecurityContext securityContext = scheduleAndReturn(Executors.defaultThreadFactory());
		assertThat(securityContext.getAuthentication()).isNotNull();
	}

	@Test
	@DisabledOnJre(JRE.JAVA_17)
	public void scheduleWhenThreadFactoryIsVirtualThenSecurityContextPropagated() throws Exception {
		SecurityContext securityContext = scheduleAndReturn(new VirtualThreadTaskExecutor().getVirtualThreadFactory());
		assertThat(securityContext.getAuthentication()).isNotNull();
	}

	private SecurityContext scheduleAndReturn(ThreadFactory threadFactory) throws Exception {
		// @formatter:off
		return DelegatingSecurityContextTestUtils.runAndReturn(
			threadFactory,
			this::createTaskScheduler,
			(taskScheduler, task) -> taskScheduler.schedule(task, new PeriodicTrigger(Duration.ofMillis(50)))
		);
		// @formatter:on
	}

	@Test
	public void scheduleAtFixedRateWhenThreadFactoryIsPlatformThenSecurityContextPropagated() throws Exception {
		SecurityContext securityContext = scheduleAtFixedRateAndReturn(Executors.defaultThreadFactory());
		assertThat(securityContext.getAuthentication()).isNotNull();
	}

	@Test
	@DisabledOnJre(JRE.JAVA_17)
	public void scheduleAtFixedRateWhenThreadFactoryIsVirtualThenSecurityContextPropagated() throws Exception {
		SecurityContext securityContext = scheduleAtFixedRateAndReturn(
				new VirtualThreadTaskExecutor().getVirtualThreadFactory());
		assertThat(securityContext.getAuthentication()).isNotNull();
	}

	private SecurityContext scheduleAtFixedRateAndReturn(ThreadFactory threadFactory) throws Exception {
		// @formatter:off
		return DelegatingSecurityContextTestUtils.runAndReturn(
			threadFactory,
			this::createTaskScheduler,
			(taskScheduler, task) -> taskScheduler.scheduleAtFixedRate(task, Duration.ofMillis(50))
		);
		// @formatter:on
	}

	@Test
	public void scheduleWithFixedDelayWhenThreadFactoryIsPlatformThenSecurityContextPropagated() throws Exception {
		SecurityContext securityContext = scheduleWithFixedDelayAndReturn(Executors.defaultThreadFactory());
		assertThat(securityContext.getAuthentication()).isNotNull();
	}

	@Test
	@DisabledOnJre(JRE.JAVA_17)
	public void scheduleWithFixedDelayWhenThreadFactoryIsVirtualThenSecurityContextPropagated() throws Exception {
		SecurityContext securityContext = scheduleWithFixedDelayAndReturn(
				new VirtualThreadTaskExecutor().getVirtualThreadFactory());
		assertThat(securityContext.getAuthentication()).isNotNull();
	}

	private SecurityContext scheduleWithFixedDelayAndReturn(ThreadFactory threadFactory) throws Exception {
		// @formatter:off
		return DelegatingSecurityContextTestUtils.runAndReturn(
			threadFactory,
			this::createTaskScheduler,
			(taskScheduler, task) -> taskScheduler.scheduleWithFixedDelay(task, Duration.ofMillis(50))
		);
		// @formatter:on
	}

	private DelegatingSecurityContextTaskScheduler createTaskScheduler(ScheduledExecutorService delegate) {
		return new DelegatingSecurityContextTaskScheduler(new ConcurrentTaskScheduler(delegate), securityContext());
	}

	private static SecurityContext securityContext() {
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(new TestingAuthenticationToken("user", null));

		return securityContext;
	}

}
