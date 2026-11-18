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

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnJre;
import org.junit.jupiter.api.condition.JRE;

import org.springframework.security.DelegatingSecurityContextTestUtils;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.ScopedSecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;

import static org.assertj.core.api.Assertions.assertThat;

@DisabledOnJre(JRE.JAVA_17)
public class ScopedDelegatingSecurityContextExecutorIntegrationTests {

	private SecurityContextHolderStrategy originalStrategy;

	@Test
	public void executeWhenSecurityContextPrecreated() throws Exception {
		SecurityContext securityContext = DelegatingSecurityContextTestUtils.runAndReturn(
		// @formatter:off
			Executors.defaultThreadFactory(),
			this::createExecutorPrecreatedContext,
			Executor::execute
			// @formatter:on
		);
		assertThat(securityContext.getAuthentication()).isNotNull();
	}

	@Test
	public void executeWhenSecurityContextInTask() throws Exception {
		SecurityContext securityContext = DelegatingSecurityContextTestUtils.runAndReturn(
		// @formatter:off
			Executors.defaultThreadFactory(),
			this::createExecutorContextInTask,
			Executor::execute
			// @formatter:on
		);
		assertThat(securityContext.getAuthentication()).isNotNull();
	}

	private DelegatingSecurityContextExecutor createExecutorPrecreatedContext(ScheduledExecutorService delegate) {
		SecurityContext securityContext = securityContext();
		DelegatingSecurityContextExecutor executor = new DelegatingSecurityContextExecutor(delegate, securityContext);
		executor.setRunnableWrapper((task) -> new ScopedSecurityContextHolderStrategy.DelegatingSecurityContextRunnable(
				securityContext, task));
		return executor;
	}

	private DelegatingSecurityContextExecutor createExecutorContextInTask(ScheduledExecutorService delegate) {
		DelegatingSecurityContextExecutor executor = new DelegatingSecurityContextExecutor(delegate, null);
		executor.setRunnableWrapper(
				(task) -> new ScopedSecurityContextHolderStrategy.DelegatingSecurityContextRunnable(null, () -> {
					SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("user", null));
					task.run();
				}));
		return executor;
	}

	private static SecurityContext securityContext() {
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(new TestingAuthenticationToken("user", null));
		return securityContext;
	}

	@BeforeEach
	public void setUpStrategy() {
		this.originalStrategy = SecurityContextHolder.getContextHolderStrategy();
		SecurityContextHolder.setContextHolderStrategy(new ScopedSecurityContextHolderStrategy());
	}

	@AfterEach
	public void restoreStrategy() {
		SecurityContextHolder.setContextHolderStrategy(this.originalStrategy);
	}

}
