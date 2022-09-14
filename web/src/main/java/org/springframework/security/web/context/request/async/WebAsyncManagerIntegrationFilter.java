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

import java.io.IOException;
import java.util.concurrent.Callable;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.Assert;
import org.springframework.web.context.request.async.WebAsyncManager;
import org.springframework.web.context.request.async.WebAsyncUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Provides integration between the {@link SecurityContext} and Spring Web's
 * {@link WebAsyncManager} by using the
 * {@link SecurityContextCallableProcessingInterceptor#beforeConcurrentHandling(org.springframework.web.context.request.NativeWebRequest, Callable)}
 * to populate the {@link SecurityContext} on the {@link Callable}.
 *
 * @author Rob Winch
 * @see SecurityContextCallableProcessingInterceptor
 */
public final class WebAsyncManagerIntegrationFilter extends OncePerRequestFilter {

	private static final Object CALLABLE_INTERCEPTOR_KEY = new Object();

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		WebAsyncManager asyncManager = WebAsyncUtils.getAsyncManager(request);
		SecurityContextCallableProcessingInterceptor securityProcessingInterceptor = (SecurityContextCallableProcessingInterceptor) asyncManager
				.getCallableInterceptor(CALLABLE_INTERCEPTOR_KEY);
		if (securityProcessingInterceptor == null) {
			SecurityContextCallableProcessingInterceptor interceptor = new SecurityContextCallableProcessingInterceptor();
			interceptor.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
			asyncManager.registerCallableInterceptor(CALLABLE_INTERCEPTOR_KEY, interceptor);
		}
		filterChain.doFilter(request, response);
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

}
