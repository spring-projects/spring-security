/*
 * Copyright 2002-2016 the original author or authors.
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

import java.util.concurrent.Callable;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * An {@link ScheduledExecutorService} which wraps each {@link Runnable} in a
 * {@link DelegatingSecurityContextRunnable} and each {@link Callable} in a
 * {@link DelegatingSecurityContextCallable}.
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class DelegatingSecurityContextScheduledExecutorService extends DelegatingSecurityContextExecutorService
		implements ScheduledExecutorService {

	/**
	 * Creates a new {@link DelegatingSecurityContextScheduledExecutorService} that uses
	 * the specified {@link SecurityContext}.
	 * @param delegateScheduledExecutorService the {@link ScheduledExecutorService} to
	 * delegate to. Cannot be null.
	 * @param securityContext the {@link SecurityContext} to use for each
	 * {@link DelegatingSecurityContextRunnable} and each
	 * {@link DelegatingSecurityContextCallable}.
	 */
	public DelegatingSecurityContextScheduledExecutorService(ScheduledExecutorService delegateScheduledExecutorService,
			SecurityContext securityContext) {
		super(delegateScheduledExecutorService, securityContext);
	}

	/**
	 * Creates a new {@link DelegatingSecurityContextScheduledExecutorService} that uses
	 * the current {@link SecurityContext} from the {@link SecurityContextHolder}.
	 * @param delegate the {@link ScheduledExecutorService} to delegate to. Cannot be
	 * null.
	 */
	public DelegatingSecurityContextScheduledExecutorService(ScheduledExecutorService delegate) {
		this(delegate, null);
	}

	@Override
	public ScheduledFuture<?> schedule(Runnable command, long delay, TimeUnit unit) {
		return getDelegate().schedule(wrap(command), delay, unit);
	}

	@Override
	public <V> ScheduledFuture<V> schedule(Callable<V> callable, long delay, TimeUnit unit) {
		return getDelegate().schedule(wrap(callable), delay, unit);
	}

	@Override
	public ScheduledFuture<?> scheduleAtFixedRate(Runnable command, long initialDelay, long period, TimeUnit unit) {
		return getDelegate().scheduleAtFixedRate(wrap(command), initialDelay, period, unit);
	}

	@Override
	public ScheduledFuture<?> scheduleWithFixedDelay(Runnable command, long initialDelay, long delay, TimeUnit unit) {
		return getDelegate().scheduleWithFixedDelay(wrap(command), initialDelay, delay, unit);
	}

	private ScheduledExecutorService getDelegate() {
		return (ScheduledExecutorService) getDelegateExecutor();
	}

}
