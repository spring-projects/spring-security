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

package org.springframework.security.concurrent;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnJre;
import org.junit.jupiter.api.condition.JRE;

import org.springframework.core.task.VirtualThreadTaskExecutor;
import org.springframework.security.DelegatingSecurityContextTestUtils;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Steve Riesenberg
 */
public class DelegatingSecurityContextExecutorIntegrationTests {

	@Test
	public void executeWhenThreadFactoryIsPlatformThenSecurityContextPropagated() throws Exception {
		SecurityContext securityContext = executeAndReturn(Executors.defaultThreadFactory());
		assertThat(securityContext.getAuthentication()).isNotNull();
	}

	@Test
	@DisabledOnJre(JRE.JAVA_17)
	public void executeWhenThreadFactoryIsVirtualThenSecurityContextPropagated() throws Exception {
		SecurityContext securityContext = executeAndReturn(new VirtualThreadTaskExecutor().getVirtualThreadFactory());
		assertThat(securityContext.getAuthentication()).isNotNull();
	}

	private SecurityContext executeAndReturn(ThreadFactory threadFactory) throws Exception {
		// @formatter:off
		return DelegatingSecurityContextTestUtils.runAndReturn(
			threadFactory,
			this::createExecutor,
			Executor::execute
		);
		// @formatter:on
	}

	private DelegatingSecurityContextExecutor createExecutor(ScheduledExecutorService delegate) {
		return new DelegatingSecurityContextExecutor(delegate, securityContext());
	}

	private static SecurityContext securityContext() {
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(new TestingAuthenticationToken("user", null));

		return securityContext;
	}

}
