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

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.core.log.LogMessage;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Populates the {@link SecurityContextHolder} with information obtained from the
 * configured {@link SecurityContextRepository} prior to the request and stores it back in
 * the repository once the request has completed and clearing the context holder. By
 * default it uses an {@link HttpSessionSecurityContextRepository}. See this class for
 * information <tt>HttpSession</tt> related configuration options.
 * <p>
 * This filter will only execute once per request, to resolve servlet container
 * (specifically Weblogic) incompatibilities.
 * <p>
 * This filter MUST be executed BEFORE any authentication processing mechanisms.
 * Authentication processing mechanisms (e.g. BASIC, CAS processing filters etc) expect
 * the <code>SecurityContextHolder</code> to contain a valid <code>SecurityContext</code>
 * by the time they execute.
 * <p>
 * This is essentially a refactoring of the old
 * <tt>HttpSessionContextIntegrationFilter</tt> to delegate the storage issues to a
 * separate strategy, allowing for more customization in the way the security context is
 * maintained between requests.
 * <p>
 * The <tt>forceEagerSessionCreation</tt> property can be used to ensure that a session is
 * always available before the filter chain executes (the default is <code>false</code>,
 * as this is resource intensive and not recommended).
 *
 * @author Luke Taylor
 * @since 3.0
 * @deprecated Use {@link SecurityContextHolderFilter}
 */
@Deprecated
public class SecurityContextPersistenceFilter extends GenericFilterBean {

	static final String FILTER_APPLIED = "__spring_security_scpf_applied";

	private SecurityContextRepository repo;

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

	private boolean forceEagerSessionCreation = false;

	public SecurityContextPersistenceFilter() {
		this(new HttpSessionSecurityContextRepository());
	}

	public SecurityContextPersistenceFilter(SecurityContextRepository repo) {
		this.repo = repo;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
	}

	private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		// ensure that filter is only applied once per request
		if (request.getAttribute(FILTER_APPLIED) != null) {
			chain.doFilter(request, response);
			return;
		}
		request.setAttribute(FILTER_APPLIED, Boolean.TRUE);
		if (this.forceEagerSessionCreation) {
			HttpSession session = request.getSession();
			if (this.logger.isDebugEnabled() && session.isNew()) {
				this.logger.debug(LogMessage.format("Created session %s eagerly", session.getId()));
			}
		}
		HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
		SecurityContext contextBeforeChainExecution = this.repo.loadContext(holder);
		try {
			this.securityContextHolderStrategy.setContext(contextBeforeChainExecution);
			if (contextBeforeChainExecution.getAuthentication() == null) {
				logger.debug("Set SecurityContextHolder to empty SecurityContext");
			}
			else {
				if (this.logger.isDebugEnabled()) {
					this.logger
							.debug(LogMessage.format("Set SecurityContextHolder to %s", contextBeforeChainExecution));
				}
			}
			chain.doFilter(holder.getRequest(), holder.getResponse());
		}
		finally {
			SecurityContext contextAfterChainExecution = this.securityContextHolderStrategy.getContext();
			// Crucial removal of SecurityContextHolder contents before anything else.
			this.securityContextHolderStrategy.clearContext();
			this.repo.saveContext(contextAfterChainExecution, holder.getRequest(), holder.getResponse());
			request.removeAttribute(FILTER_APPLIED);
			this.logger.debug("Cleared SecurityContextHolder to complete request");
		}
	}

	public void setForceEagerSessionCreation(boolean forceEagerSessionCreation) {
		this.forceEagerSessionCreation = forceEagerSessionCreation;
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
