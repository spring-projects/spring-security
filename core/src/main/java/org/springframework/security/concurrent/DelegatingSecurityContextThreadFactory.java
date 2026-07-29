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

import java.util.concurrent.ThreadFactory;

import org.jspecify.annotations.Nullable;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.Assert;

/**
 * A {@link ThreadFactory} which wraps each {@link Runnable} in a
 * {@link DelegatingSecurityContextRunnable}.
 *
 * @author klouds27 (Adolfo G)
 * @since 6.5
 */
public final class DelegatingSecurityContextThreadFactory extends AbstractDelegatingSecurityContextSupport
		implements ThreadFactory {

	private final ThreadFactory delegate;

	/**
	 * Creates a new {@link DelegatingSecurityContextThreadFactory} that uses the
	 * specified {@link SecurityContext}.
	 * @param delegateThreadFactory the {@link ThreadFactory} to delegate to. Cannot be
	 * null.
	 * @param securityContext the {@link SecurityContext} to use for each
	 * {@link DelegatingSecurityContextRunnable} or null to default to the current
	 * {@link SecurityContext}
	 */
	public DelegatingSecurityContextThreadFactory(ThreadFactory delegateThreadFactory,
			@Nullable SecurityContext securityContext) {
		super(securityContext);
		Assert.notNull(delegateThreadFactory, "delegateThreadFactory cannot be null");
		this.delegate = delegateThreadFactory;
	}

	/**
	 * Creates a new {@link DelegatingSecurityContextThreadFactory} that uses the current
	 * {@link SecurityContext} from the {@link SecurityContextHolder} at the time each
	 * thread is created.
	 * @param delegate the {@link ThreadFactory} to delegate to. Cannot be null.
	 */
	public DelegatingSecurityContextThreadFactory(ThreadFactory delegate) {
		this(delegate, null);
	}

	@Override
	public Thread newThread(Runnable r) {
		return this.delegate.newThread(wrap(r));
	}

	/**
	 * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
	 * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
	 *
	 * @since 6.5
	 */
	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		super.setSecurityContextHolderStrategy(securityContextHolderStrategy);
	}

}
