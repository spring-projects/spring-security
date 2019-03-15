/*
 * Copyright 2002-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.concurrent;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.springframework.core.task.TaskExecutor;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * An {@link ExecutorService} which wraps each {@link Runnable} in a {@link DelegatingSecurityContextRunnable} and each
 * {@link Callable} in a {@link DelegatingSecurityContextCallable}.
 *
 * @author Rob Winch
 * @since 3.2
 */
public class DelegatingSecurityContextExecutorService extends DelegatingSecurityContextExecutor implements
        ExecutorService {
    /**
     * Creates a new {@link DelegatingSecurityContextExecutorService} that uses the specified {@link SecurityContext}.
     *
     * @param delegateExecutorService the {@link ExecutorService} to delegate to. Cannot be null.
     * @param securityContext the {@link SecurityContext} to use for each {@link DelegatingSecurityContextRunnable} and
     * each {@link DelegatingSecurityContextCallable}.
     */
    public DelegatingSecurityContextExecutorService(ExecutorService delegateExecutorService,
            SecurityContext securityContext) {
        super(delegateExecutorService, securityContext);
    }

    /**
     * Creates a new {@link DelegatingSecurityContextExecutorService} that uses the current {@link SecurityContext} from
     * the {@link SecurityContextHolder}.
     *
     * @param delegateTaskExecutor the {@link TaskExecutor} to delegate to. Cannot be null.
     */
    public DelegatingSecurityContextExecutorService(ExecutorService delegate) {
        this(delegate, null);
    }

    public final void shutdown() {
        getDelegate().shutdown();
    }

    public final List<Runnable> shutdownNow() {
        return getDelegate().shutdownNow();
    }

    public final boolean isShutdown() {
        return getDelegate().isShutdown();
    }

    public final boolean isTerminated() {
        return getDelegate().isTerminated();
    }

    public final boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException {
        return getDelegate().awaitTermination(timeout, unit);
    }

    public final <T> Future<T> submit(Callable<T> task) {
        task = wrap(task);
        return getDelegate().submit(task);
    }

    public final <T> Future<T> submit(Runnable task, T result) {
        task = wrap(task);
        return getDelegate().submit(task, result);
    }

    public final Future<?> submit(Runnable task) {
        task = wrap(task);
        return getDelegate().submit(task);
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    public final List invokeAll(Collection tasks) throws InterruptedException {
        tasks = createTasks(tasks);
        return getDelegate().invokeAll(tasks);
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    public final List invokeAll(Collection tasks, long timeout, TimeUnit unit)
            throws InterruptedException {
        tasks = createTasks(tasks);
        return getDelegate().invokeAll(tasks, timeout, unit);
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    public final Object invokeAny(Collection tasks) throws InterruptedException, ExecutionException {
        tasks = createTasks(tasks);
        return getDelegate().invokeAny(tasks);
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    public final Object invokeAny(Collection tasks, long timeout, TimeUnit unit)
            throws InterruptedException, ExecutionException, TimeoutException {
        tasks = createTasks(tasks);
        return getDelegate().invokeAny(tasks, timeout, unit);
    }

    private <T> Collection<Callable<T>> createTasks(Collection<Callable<T>> tasks) {
        if (tasks == null) {
            return null;
        }
        List<Callable<T>> results = new ArrayList<Callable<T>>(tasks.size());
        for (Callable<T> task : tasks) {
            results.add(wrap(task));
        }
        return results;
    }

    private ExecutorService getDelegate() {
        return (ExecutorService) getDelegateExecutor();
    }
}