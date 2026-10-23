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

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnJre;
import org.junit.jupiter.api.condition.JRE;

import org.springframework.core.task.VirtualThreadTaskExecutor;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * @author klouds27 (Adolfo G)
 */
public class DelegatingSecurityContextThreadFactoryTests {

	@AfterEach
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void constructorWhenNullDelegateThenException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new DelegatingSecurityContextThreadFactory(null, null));
	}

	@Test
	public void newThreadWhenPlatformThreadThenSecurityContextPropagated() throws Exception {
		SecurityContext context = propagateAndCapture(Executors.defaultThreadFactory());
		assertThat(context.getAuthentication()).isNotNull();
	}

	@Test
	@DisabledOnJre(JRE.JAVA_17)
	public void newThreadWhenVirtualThreadThenSecurityContextPropagated() throws Exception {
		SecurityContext context = propagateAndCapture(new VirtualThreadTaskExecutor().getVirtualThreadFactory());
		assertThat(context.getAuthentication()).isNotNull();
	}

	@Test
	public void newThreadWhenExplicitSecurityContextThenUsesThatContext() throws Exception {
		SecurityContext explicit = SecurityContextHolder.createEmptyContext();
		explicit.setAuthentication(new TestingAuthenticationToken("explicit", null));
		DelegatingSecurityContextThreadFactory factory = new DelegatingSecurityContextThreadFactory(
				Executors.defaultThreadFactory(), explicit);
		SecurityContext captured = runAndCapture(factory);
		assertThat(captured.getAuthentication().getName()).isEqualTo("explicit");
	}

	@Test
	public void newThreadWhenCurrentContextThenPropagatesCallerContext() throws Exception {
		SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(new TestingAuthenticationToken("caller", null));
		SecurityContextHolder.setContext(context);
		DelegatingSecurityContextThreadFactory factory = new DelegatingSecurityContextThreadFactory(
				Executors.defaultThreadFactory());
		SecurityContext captured = runAndCapture(factory);
		assertThat(captured.getAuthentication().getName()).isEqualTo("caller");
	}

	private SecurityContext propagateAndCapture(ThreadFactory threadFactory) throws Exception {
		SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(new TestingAuthenticationToken("user", null));
		DelegatingSecurityContextThreadFactory factory = new DelegatingSecurityContextThreadFactory(threadFactory,
				context);
		return runAndCapture(factory);
	}

	private SecurityContext runAndCapture(DelegatingSecurityContextThreadFactory factory) throws InterruptedException {
		CountDownLatch latch = new CountDownLatch(1);
		AtomicReference<SecurityContext> result = new AtomicReference<>();
		Thread thread = factory.newThread(() -> {
			result.set(SecurityContextHolder.getContext());
			latch.countDown();
		});
		thread.start();
		latch.await();
		return result.get();
	}

}
