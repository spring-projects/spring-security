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
 * An internal support class that wraps {@link Callable} with
 * {@link DelegatingSecurityContextCallable} and {@link Runnable} with
 * {@link DelegatingSecurityContextRunnable}
 *
 * @author Rob Winch
 * @since 3.2
 */
abstract class AbstractDelegatingSecurityContextSupport {

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

	private final SecurityContext securityContext;

	/**
	 * Creates a new {@link AbstractDelegatingSecurityContextSupport} that uses the
	 * specified {@link SecurityContext}.
	 * @param securityContext the {@link SecurityContext} to use for each
	 * {@link DelegatingSecurityContextRunnable} and each
	 * {@link DelegatingSecurityContextCallable} or null to default to the current
	 * {@link SecurityContext}.
	 */
	AbstractDelegatingSecurityContextSupport(SecurityContext securityContext) {
		this.securityContext = securityContext;
	}

	void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

	protected final Runnable wrap(Runnable delegate) {
		return DelegatingSecurityContextRunnable.create(delegate, this.securityContext,
				this.securityContextHolderStrategy);
	}

	protected final <T> Callable<T> wrap(Callable<T> delegate) {
		return DelegatingSecurityContextCallable.create(delegate, this.securityContext,
				this.securityContextHolderStrategy);
	}

}
