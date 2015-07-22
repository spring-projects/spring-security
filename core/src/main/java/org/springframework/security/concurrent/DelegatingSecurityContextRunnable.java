/*
 * Copyright 2002-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.concurrent;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

/**
 * <p>
 * Wraps a delegate {@link Runnable} with logic for setting up a {@link SecurityContext}
 * before invoking the delegate {@link Runnable} and then removing the
 * {@link SecurityContext} after the delegate has completed.
 * </p>
 * <p>
 * By default the {@link SecurityContext} is only setup if {@link #run()} is
 * invoked on a separate {@link Thread} than the
 * {@link DelegatingSecurityContextRunnable} was created on. This can be
 * overridden by setting {@link #setEnableOnOriginalThread(boolean)} to true.
 * </p>
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class DelegatingSecurityContextRunnable implements Runnable {

    private final Runnable delegate;

    private final SecurityContext securityContext;

    private final Thread originalThread;

    private boolean enableOnOriginalThread;

    /**
     * Creates a new {@link DelegatingSecurityContextRunnable} with a specific {@link SecurityContext}.
     * @param delegate the delegate {@link Runnable} to run with the specified {@link SecurityContext}. Cannot be null.
     * @param securityContext the {@link SecurityContext} to establish for the delegate {@link Runnable}. Cannot be
     * null.
     */
    public DelegatingSecurityContextRunnable(Runnable delegate, SecurityContext securityContext) {
        Assert.notNull(delegate, "delegate cannot be null");
        Assert.notNull(securityContext, "securityContext cannot be null");
        this.delegate = delegate;
        this.securityContext = securityContext;
        this.originalThread = Thread.currentThread();
    }

    /**
     * Creates a new {@link DelegatingSecurityContextRunnable} with the {@link SecurityContext} from the
     * {@link SecurityContextHolder}.
     * @param delegate the delegate {@link Runnable} to run under the current {@link SecurityContext}. Cannot be null.
     */
    public DelegatingSecurityContextRunnable(Runnable delegate) {
        this(delegate, SecurityContextHolder.getContext());
    }

    /**
     * Determines if the SecurityContext should be transfered if {@link #call()}
     * is invoked on the same {@link Thread} the
     * {@link DelegatingSecurityContextCallable} was created on.
     *
     * @param enableOnOriginalThread
     *            if false (default), will only transfer the
     *            {@link SecurityContext} if {@link #call()} is invoked on a
     *            different {@link Thread} than the
     *            {@link DelegatingSecurityContextCallable} was created on.
     * @since 4.0.2
     */
    public void setEnableOnOriginalThread(boolean enableOnOriginalThread) {
        this.enableOnOriginalThread = enableOnOriginalThread;
    }

    public void run() {
        if(!enableOnOriginalThread && originalThread == Thread.currentThread()) {
            delegate.run();
            return;
        }
        try {
            SecurityContextHolder.setContext(securityContext);
            delegate.run();
        }
        finally {
            SecurityContextHolder.clearContext();
        }
    }

    public String toString() {
        return delegate.toString();
    }

    /**
     * Factory method for creating a {@link DelegatingSecurityContextRunnable}.
     *
     * @param delegate the original {@link Runnable} that will be delegated to after establishing a
     * {@link SecurityContext} on the {@link SecurityContextHolder}. Cannot have null.
     * @param securityContext the {@link SecurityContext} to establish before invoking the delegate {@link Runnable}. If
     * null, the current {@link SecurityContext} from the {@link SecurityContextHolder} will be used.
     * @return
     */
    public static Runnable create(Runnable delegate, SecurityContext securityContext) {
        Assert.notNull(delegate, "delegate cannot be  null");
        return securityContext == null ? new DelegatingSecurityContextRunnable(delegate)
                : new DelegatingSecurityContextRunnable(delegate, securityContext);
    }
}
