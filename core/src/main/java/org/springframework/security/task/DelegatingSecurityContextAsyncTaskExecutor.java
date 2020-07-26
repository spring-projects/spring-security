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
package org.springframework.security.task;

import java.util.concurrent.Callable;
import java.util.concurrent.Future;

import org.springframework.core.task.AsyncTaskExecutor;
import org.springframework.security.concurrent.DelegatingSecurityContextCallable;
import org.springframework.security.concurrent.DelegatingSecurityContextRunnable;
import org.springframework.security.core.context.SecurityContext;

/**
 * An {@link AsyncTaskExecutor} which wraps each {@link Runnable} in a
 * {@link DelegatingSecurityContextRunnable} and each {@link Callable} in a
 * {@link DelegatingSecurityContextCallable}.
 *
 * @author Rob Winch
 * @since 3.2
 */
public class DelegatingSecurityContextAsyncTaskExecutor extends DelegatingSecurityContextTaskExecutor
		implements AsyncTaskExecutor {

	/**
	 * Creates a new {@link DelegatingSecurityContextAsyncTaskExecutor} that uses the
	 * specified {@link SecurityContext}.
	 * @param delegateAsyncTaskExecutor the {@link AsyncTaskExecutor} to delegate to.
	 * Cannot be null.
	 * @param securityContext the {@link SecurityContext} to use for each
	 * {@link DelegatingSecurityContextRunnable} and
	 * {@link DelegatingSecurityContextCallable}
	 */
	public DelegatingSecurityContextAsyncTaskExecutor(AsyncTaskExecutor delegateAsyncTaskExecutor,
			SecurityContext securityContext) {
		super(delegateAsyncTaskExecutor, securityContext);
	}

	/**
	 * Creates a new {@link DelegatingSecurityContextAsyncTaskExecutor} that uses the
	 * current {@link SecurityContext}.
	 * @param delegateAsyncTaskExecutor the {@link AsyncTaskExecutor} to delegate to.
	 * Cannot be null.
	 */
	public DelegatingSecurityContextAsyncTaskExecutor(AsyncTaskExecutor delegateAsyncTaskExecutor) {
		this(delegateAsyncTaskExecutor, null);
	}

	@Override
	public final void execute(Runnable task, long startTimeout) {
		task = wrap(task);
		getDelegate().execute(task, startTimeout);
	}

	@Override
	public final Future<?> submit(Runnable task) {
		task = wrap(task);
		return getDelegate().submit(task);
	}

	@Override
	public final <T> Future<T> submit(Callable<T> task) {
		task = wrap(task);
		return getDelegate().submit(task);
	}

	private AsyncTaskExecutor getDelegate() {
		return (AsyncTaskExecutor) getDelegateExecutor();
	}

}
