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

import java.util.concurrent.Callable;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

/**
 * Wraps a delegate {@link Callable} with logic for setting up a {@link SecurityContext} before invoking the delegate
 * {@link Callable} and then removing the {@link SecurityContext} after the delegate has completed.
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class DelegatingSecurityContextCallable<V> implements Callable<V> {

    private final Callable<V> delegate;

    private final SecurityContext securityContext;

    /**
     * Creates a new {@link DelegatingSecurityContextCallable} with a specific {@link SecurityContext}.
     * @param delegate the delegate {@link DelegatingSecurityContextCallable} to run with the specified
     * {@link SecurityContext}. Cannot be null.
     * @param securityContext the {@link SecurityContext} to establish for the delegate {@link Callable}. Cannot be
     * null.
     */
    public DelegatingSecurityContextCallable(Callable<V> delegate, SecurityContext securityContext) {
        Assert.notNull(delegate, "delegate cannot be null");
        Assert.notNull(securityContext, "securityContext cannot be null");
        this.delegate = delegate;
        this.securityContext = securityContext;
    }

    /**
     * Creates a new {@link DelegatingSecurityContextCallable} with the {@link SecurityContext} from the
     * {@link SecurityContextHolder}.
     * @param delegate the delegate {@link Callable} to run under the current {@link SecurityContext}. Cannot be null.
     */
    public DelegatingSecurityContextCallable(Callable<V> delegate) {
        this(delegate, SecurityContextHolder.getContext());
    }

    public V call() throws Exception {
        try {
            SecurityContextHolder.setContext(securityContext);
            return delegate.call();
        }
        finally {
            SecurityContextHolder.clearContext();
        }
    }

    /**
     * Creates a {@link DelegatingSecurityContextCallable} and with the given {@link Callable} and
     * {@link SecurityContext}, but if the securityContext is null will defaults to the current {@link SecurityContext}
     * on the {@link SecurityContextHolder}
     *
     * @param delegate the delegate {@link DelegatingSecurityContextCallable} to run with the specified
     * {@link SecurityContext}. Cannot be null.
     * @param securityContext the {@link SecurityContext} to establish for the delegate {@link Callable}. If null,
     * defaults to {@link SecurityContextHolder#getContext()}
     * @return
     */
    public static <V> Callable<V> create(Callable<V> delegate, SecurityContext securityContext) {
        return securityContext == null ? new DelegatingSecurityContextCallable<V>(delegate)
                : new DelegatingSecurityContextCallable<V>(delegate, securityContext);
    }
}
