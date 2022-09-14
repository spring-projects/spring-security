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

package org.springframework.security.web.context.request.async;

import java.util.concurrent.Callable;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.Assert;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.async.CallableProcessingInterceptor;

/**
 * <p>
 * Allows for integration with Spring MVC's {@link Callable} support.
 * </p>
 * <p>
 * A {@link CallableProcessingInterceptor} that establishes the injected
 * {@link SecurityContext} on the {@link SecurityContextHolder} when
 * {@link #preProcess(NativeWebRequest, Callable)} is invoked. It also clear out the
 * {@link SecurityContextHolder} by invoking {@link SecurityContextHolder#clearContext()}
 * in the {@link #postProcess(NativeWebRequest, Callable, Object)} method.
 * </p>
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class SecurityContextCallableProcessingInterceptor implements CallableProcessingInterceptor {

	private volatile SecurityContext securityContext;

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

	/**
	 * Create a new {@link SecurityContextCallableProcessingInterceptor} that uses the
	 * {@link SecurityContext} from the {@link SecurityContextHolder} at the time
	 * {@link #beforeConcurrentHandling(NativeWebRequest, Callable)} is invoked.
	 */
	public SecurityContextCallableProcessingInterceptor() {
	}

	/**
	 * Creates a new {@link SecurityContextCallableProcessingInterceptor} with the
	 * specified {@link SecurityContext}.
	 * @param securityContext the {@link SecurityContext} to set on the
	 * {@link SecurityContextHolder} in {@link #preProcess(NativeWebRequest, Callable)}.
	 * Cannot be null.
	 * @throws IllegalArgumentException if {@link SecurityContext} is null.
	 */
	public SecurityContextCallableProcessingInterceptor(SecurityContext securityContext) {
		Assert.notNull(securityContext, "securityContext cannot be null");
		setSecurityContext(securityContext);
	}

	@Override
	public <T> void beforeConcurrentHandling(NativeWebRequest request, Callable<T> task) {
		if (this.securityContext == null) {
			setSecurityContext(this.securityContextHolderStrategy.getContext());
		}
	}

	@Override
	public <T> void preProcess(NativeWebRequest request, Callable<T> task) {
		this.securityContextHolderStrategy.setContext(this.securityContext);
	}

	@Override
	public <T> void postProcess(NativeWebRequest request, Callable<T> task, Object concurrentResult) {
		this.securityContextHolderStrategy.clearContext();
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
	}

	private void setSecurityContext(SecurityContext securityContext) {
		this.securityContext = securityContext;
	}

}
