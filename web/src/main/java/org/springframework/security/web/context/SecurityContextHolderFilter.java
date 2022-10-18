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

package org.springframework.security.web.context;

import java.io.IOException;
import java.util.function.Supplier;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A {@link jakarta.servlet.Filter} that uses the {@link SecurityContextRepository} to
 * obtain the {@link SecurityContext} and set it on the {@link SecurityContextHolder}.
 * This is similar to {@link SecurityContextPersistenceFilter} except that the
 * {@link SecurityContextRepository#saveContext(SecurityContext, HttpServletRequest, HttpServletResponse)}
 * must be explicitly invoked to save the {@link SecurityContext}. This improves the
 * efficiency and provides better flexibility by allowing different authentication
 * mechanisms to choose individually if authentication should be persisted.
 *
 * @author Rob Winch
 * @since 5.7
 */
public class SecurityContextHolderFilter extends OncePerRequestFilter {

	private final SecurityContextRepository securityContextRepository;

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

	private boolean shouldNotFilterErrorDispatch;

	/**
	 * Creates a new instance.
	 * @param securityContextRepository the repository to use. Cannot be null.
	 */
	public SecurityContextHolderFilter(SecurityContextRepository securityContextRepository) {
		Assert.notNull(securityContextRepository, "securityContextRepository cannot be null");
		this.securityContextRepository = securityContextRepository;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		Supplier<SecurityContext> deferredContext = this.securityContextRepository.loadDeferredContext(request);
		try {
			this.securityContextHolderStrategy.setDeferredContext(deferredContext);
			filterChain.doFilter(request, response);
		}
		finally {
			this.securityContextHolderStrategy.clearContext();
		}
	}

	@Override
	protected boolean shouldNotFilterErrorDispatch() {
		return this.shouldNotFilterErrorDispatch;
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

	/**
	 * Disables {@link SecurityContextHolderFilter} for error dispatch.
	 * @param shouldNotFilterErrorDispatch if the Filter should be disabled for error
	 * dispatch. Default is false.
	 */
	public void setShouldNotFilterErrorDispatch(boolean shouldNotFilterErrorDispatch) {
		this.shouldNotFilterErrorDispatch = shouldNotFilterErrorDispatch;
	}

}
