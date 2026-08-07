/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.core.context.ScopedSecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * A {@link jakarta.servlet.Filter} that orchestrates the usage of
 * {@link ScopedSecurityContextHolderStrategy}.
 *
 * <p>
 * </p>
 * The implementation is very similar to that of {@link SecurityContextHolderFilter},
 * where from it has been adopted, except the delegating to the next filter has to be an
 * operation passed to {@link ScopedValue.Carrier#run(Runnable)} method, so that for every
 * code executed up-stack of this filter a {@link ScopedValue} is bound to a
 * {@link org.springframework.security.core.context.SecurityContext SecurityContext}
 * instance for the current thread.
 *
 * <p>
 * </p>
 * The other difference is that
 * {@link #setSecurityContextHolderStrategy(SecurityContextHolderStrategy)} method can
 * accept only {@link ScopedSecurityContextHolderStrategy} implementation of
 * {@link SecurityContextHolderStrategy} interface.
 *
 * @see org.springframework.security.core.context.ScopedSecurityContextHolderStrategy
 */
public class ScopedSecurityContextHolderFilter extends GenericFilterBean {

	private static final String FILTER_APPLIED = ScopedSecurityContextHolderFilter.class.getName() + ".APPLIED";

	private final SecurityContextRepository securityContextRepository;

	private ScopedSecurityContextHolderStrategy securityContextHolderStrategy;

	public ScopedSecurityContextHolderFilter(SecurityContextRepository securityContextRepository) {
		this.securityContextRepository = securityContextRepository;
		final SecurityContextHolderStrategy contextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
		this.securityContextHolderStrategy = (contextHolderStrategy instanceof ScopedSecurityContextHolderStrategy)
				? (ScopedSecurityContextHolderStrategy) contextHolderStrategy
				: new ScopedSecurityContextHolderStrategy();
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
	}

	private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		if (request.getAttribute(FILTER_APPLIED) != null) {
			chain.doFilter(request, response);
			return;
		}
		request.setAttribute(FILTER_APPLIED, Boolean.TRUE);
		DeferredSecurityContext deferredContext = this.securityContextRepository.loadDeferredContext(request);
		try {
			ScopedSecurityContextHolderStrategy.runWhere(deferredContext, () -> {
				this.securityContextHolderStrategy.setDeferredContext(deferredContext);
				try {
					chain.doFilter(request, response);
				}
				catch (IOException | ServletException ex) {
					throw new RuntimeException(ex);
				}
			});
		}
		catch (RuntimeException ex) {
			final Throwable cause = ex.getCause();
			if (cause instanceof ServletException) {
				throw (ServletException) cause;
			}
			if (cause instanceof IOException) {
				throw (IOException) cause;
			}
			throw ex;
		}
		finally {
			// clearing the Context is unnecessary because ScopedValue is already unbound
			request.removeAttribute(FILTER_APPLIED);
		}
	}

	/**
	 * Only {@link ScopedSecurityContextHolderStrategy} implementation of
	 * {@link SecurityContextHolderStrategy} interface is acceptable, otherwise
	 * {@link IllegalArgumentException} is thrown
	 * @param securityContextHolderStrategy
	 */
	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.isInstanceOf(ScopedSecurityContextHolderStrategy.class, securityContextHolderStrategy,
				"Security Context Holder Strategy is not of type "
						+ ScopedSecurityContextHolderStrategy.class.getSimpleName());
		this.securityContextHolderStrategy = (ScopedSecurityContextHolderStrategy) securityContextHolderStrategy;
	}

}
