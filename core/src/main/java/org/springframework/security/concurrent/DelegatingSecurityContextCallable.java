/*
 * Copyright 2002-2022 the original author or authors.
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

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.Assert;

/**
 * <p>
 * Wraps a delegate {@link Callable} with logic for setting up a {@link SecurityContext}
 * before invoking the delegate {@link Callable} and then removing the
 * {@link SecurityContext} after the delegate has completed.
 * </p>
 * <p>
 * If there is a {@link SecurityContext} that already exists, it will be restored after
 * the {@link #call()} method is invoked.
 * </p>
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class DelegatingSecurityContextCallable<V> implements Callable<V> {

	private final Callable<V> delegate;

	private final boolean explicitSecurityContextProvided;

	/**
	 * The {@link SecurityContext} that the delegate {@link Callable} will be ran as.
	 */
	private SecurityContext delegateSecurityContext;

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

	/**
	 * The {@link SecurityContext} that was on the {@link SecurityContextHolder} prior to
	 * being set to the delegateSecurityContext.
	 */
	private SecurityContext originalSecurityContext;

	/**
	 * Creates a new {@link DelegatingSecurityContextCallable} with a specific
	 * {@link SecurityContext}.
	 * @param delegate the delegate {@link DelegatingSecurityContextCallable} to run with
	 * the specified {@link SecurityContext}. Cannot be null.
	 * @param securityContext the {@link SecurityContext} to establish for the delegate
	 * {@link Callable}. Cannot be null.
	 */
	public DelegatingSecurityContextCallable(Callable<V> delegate, SecurityContext securityContext) {
		this(delegate, securityContext, true);
	}

	/**
	 * Creates a new {@link DelegatingSecurityContextCallable} with the
	 * {@link SecurityContext} from the {@link SecurityContextHolder}.
	 * @param delegate the delegate {@link Callable} to run under the current
	 * {@link SecurityContext}. Cannot be null.
	 */
	public DelegatingSecurityContextCallable(Callable<V> delegate) {
		this(delegate, SecurityContextHolder.getContext(), false);
	}

	private DelegatingSecurityContextCallable(Callable<V> delegate, SecurityContext securityContext,
			boolean explicitSecurityContextProvided) {
		Assert.notNull(delegate, "delegate cannot be null");
		Assert.notNull(securityContext, "securityContext cannot be null");
		this.delegate = delegate;
		this.delegateSecurityContext = securityContext;
		this.explicitSecurityContextProvided = explicitSecurityContextProvided;
	}

	@Override
	public V call() throws Exception {
		this.originalSecurityContext = this.securityContextHolderStrategy.getContext();
		try {
			this.securityContextHolderStrategy.setContext(this.delegateSecurityContext);
			return this.delegate.call();
		}
		finally {
			SecurityContext emptyContext = this.securityContextHolderStrategy.createEmptyContext();
			if (emptyContext.equals(this.originalSecurityContext)) {
				this.securityContextHolderStrategy.clearContext();
			}
			else {
				this.securityContextHolderStrategy.setContext(this.originalSecurityContext);
			}
			this.originalSecurityContext = null;
		}
	}

	/**
	 * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
	 * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
	 *
	 * @since 5.8
	 */
	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
		this.securityContextHolderStrategy = securityContextHolderStrategy;
		if (!this.explicitSecurityContextProvided) {
			this.delegateSecurityContext = securityContextHolderStrategy.getContext();
		}
	}

	@Override
	public String toString() {
		return this.delegate.toString();
	}

	/**
	 * Creates a {@link DelegatingSecurityContextCallable} and with the given
	 * {@link Callable} and {@link SecurityContext}, but if the securityContext is null
	 * will defaults to the current {@link SecurityContext} on the
	 * {@link SecurityContextHolder}
	 * @param delegate the delegate {@link DelegatingSecurityContextCallable} to run with
	 * the specified {@link SecurityContext}. Cannot be null.
	 * @param securityContext the {@link SecurityContext} to establish for the delegate
	 * {@link Callable}. If null, defaults to {@link SecurityContextHolder#getContext()}
	 * @return
	 */
	public static <V> Callable<V> create(Callable<V> delegate, SecurityContext securityContext) {
		return (securityContext != null) ? new DelegatingSecurityContextCallable<>(delegate, securityContext)
				: new DelegatingSecurityContextCallable<>(delegate);
	}

	static <V> Callable<V> create(Callable<V> delegate, SecurityContext securityContext,
			SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.notNull(delegate, "delegate cannot be null");
		Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
		DelegatingSecurityContextCallable<V> callable = (securityContext != null)
				? new DelegatingSecurityContextCallable<>(delegate, securityContext)
				: new DelegatingSecurityContextCallable<>(delegate);
		callable.setSecurityContextHolderStrategy(securityContextHolderStrategy);
		return callable;
	}

}
