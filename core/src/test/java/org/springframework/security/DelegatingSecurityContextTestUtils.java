/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security;

import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Function;

import org.springframework.scheduling.TaskScheduler;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * @author Steve Riesenberg
 */
public final class DelegatingSecurityContextTestUtils {

	private DelegatingSecurityContextTestUtils() {
	}

	public static <T extends Executor> SecurityContext runAndReturn(ThreadFactory threadFactory,
			Function<ScheduledExecutorService, T> factory, BiConsumer<T, Runnable> fn) throws Exception {
		CountDownLatch countDownLatch = new CountDownLatch(1);
		AtomicReference<SecurityContext> result = new AtomicReference<>();
		ScheduledExecutorService delegate = Executors.newSingleThreadScheduledExecutor(threadFactory);
		try {
			T executor = factory.apply(delegate);
			Runnable task = () -> {
				result.set(SecurityContextHolder.getContext());
				countDownLatch.countDown();
			};
			fn.accept(executor, task);
			countDownLatch.await();

			return result.get();
		}
		finally {
			delegate.shutdown();
		}
	}

	public static <T extends TaskScheduler> SecurityContext runAndReturn(ThreadFactory threadFactory,
			Function<ScheduledExecutorService, T> factory, BiFunction<T, Runnable, ScheduledFuture<?>> fn)
			throws Exception {
		CountDownLatch countDownLatch = new CountDownLatch(1);
		AtomicReference<SecurityContext> result = new AtomicReference<>();
		ScheduledExecutorService delegate = Executors.newSingleThreadScheduledExecutor(threadFactory);
		try {
			T taskScheduler = factory.apply(delegate);
			Runnable task = () -> {
				result.set(SecurityContextHolder.getContext());
				countDownLatch.countDown();
			};
			ScheduledFuture<?> future = fn.apply(taskScheduler, task);
			countDownLatch.await();
			future.cancel(false);

			return result.get();
		}
		finally {
			delegate.shutdown();
		}
	}

	public static <T extends Executor> SecurityContext callAndReturn(ThreadFactory threadFactory,
			Function<ScheduledExecutorService, T> factory,
			BiFunction<T, Callable<SecurityContext>, Future<SecurityContext>> fn) throws Exception {
		ScheduledExecutorService delegate = Executors.newSingleThreadScheduledExecutor(threadFactory);
		try {
			T executor = factory.apply(delegate);
			Callable<SecurityContext> task = SecurityContextHolder::getContext;
			return fn.apply(executor, task).get();
		}
		finally {
			delegate.shutdown();
		}
	}

}
