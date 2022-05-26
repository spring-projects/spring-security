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

package org.springframework.security.web.session;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Detects that a user has been authenticated since the start of the request and, if they
 * have, calls the configured {@link SessionAuthenticationStrategy} to perform any
 * session-related activity such as activating session-fixation protection mechanisms or
 * checking for multiple concurrent logins.
 *
 * @author Martin Algesten
 * @author Luke Taylor
 * @since 2.0
 */
public class SessionManagementFilter extends GenericFilterBean {

	static final String FILTER_APPLIED = "__spring_security_session_mgmt_filter_applied";

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

	private final SecurityContextRepository securityContextRepository;

	private SessionAuthenticationStrategy sessionAuthenticationStrategy;

	private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

	private InvalidSessionStrategy invalidSessionStrategy = null;

	private AuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler();

	public SessionManagementFilter(SecurityContextRepository securityContextRepository) {
		this(securityContextRepository, new SessionFixationProtectionStrategy());
	}

	public SessionManagementFilter(SecurityContextRepository securityContextRepository,
			SessionAuthenticationStrategy sessionStrategy) {
		Assert.notNull(securityContextRepository, "SecurityContextRepository cannot be null");
		Assert.notNull(sessionStrategy, "SessionAuthenticationStrategy cannot be null");
		this.securityContextRepository = securityContextRepository;
		this.sessionAuthenticationStrategy = sessionStrategy;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
	}

	private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		if (request.getAttribute(FILTER_APPLIED) != null) {
			chain.doFilter(request, response);
			return;
		}
		request.setAttribute(FILTER_APPLIED, Boolean.TRUE);
		if (!this.securityContextRepository.containsContext(request)) {
			Authentication authentication = this.securityContextHolderStrategy.getContext().getAuthentication();
			if (authentication != null && !this.trustResolver.isAnonymous(authentication)) {
				// The user has been authenticated during the current request, so call the
				// session strategy
				try {
					this.sessionAuthenticationStrategy.onAuthentication(authentication, request, response);
				}
				catch (SessionAuthenticationException ex) {
					// The session strategy can reject the authentication
					this.logger.debug("SessionAuthenticationStrategy rejected the authentication object", ex);
					this.securityContextHolderStrategy.clearContext();
					this.failureHandler.onAuthenticationFailure(request, response, ex);
					return;
				}
				// Eagerly save the security context to make it available for any possible
				// re-entrant requests which may occur before the current request
				// completes. SEC-1396.
				this.securityContextRepository.saveContext(this.securityContextHolderStrategy.getContext(), request,
						response);
			}
			else {
				// No security context or authentication present. Check for a session
				// timeout
				if (request.getRequestedSessionId() != null && !request.isRequestedSessionIdValid()) {
					if (this.logger.isDebugEnabled()) {
						this.logger.debug(LogMessage.format("Request requested invalid session id %s",
								request.getRequestedSessionId()));
					}
					if (this.invalidSessionStrategy != null) {
						this.invalidSessionStrategy.onInvalidSessionDetected(request, response);
						return;
					}
				}
			}
		}
		chain.doFilter(request, response);
	}

	/**
	 * Sets the strategy which will be invoked instead of allowing the filter chain to
	 * proceed, if the user agent requests an invalid session ID. If the property is not
	 * set, no action will be taken.
	 * @param invalidSessionStrategy the strategy to invoke. Typically a
	 * {@link SimpleRedirectInvalidSessionStrategy}.
	 */
	public void setInvalidSessionStrategy(InvalidSessionStrategy invalidSessionStrategy) {
		this.invalidSessionStrategy = invalidSessionStrategy;
	}

	/**
	 * The handler which will be invoked if the <tt>AuthenticatedSessionStrategy</tt>
	 * raises a <tt>SessionAuthenticationException</tt>, indicating that the user is not
	 * allowed to be authenticated for this session (typically because they already have
	 * too many sessions open).
	 *
	 */
	public void setAuthenticationFailureHandler(AuthenticationFailureHandler failureHandler) {
		Assert.notNull(failureHandler, "failureHandler cannot be null");
		this.failureHandler = failureHandler;
	}

	/**
	 * Sets the {@link AuthenticationTrustResolver} to be used. The default is
	 * {@link AuthenticationTrustResolverImpl}.
	 * @param trustResolver the {@link AuthenticationTrustResolver} to use. Cannot be
	 * null.
	 */
	public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
		Assert.notNull(trustResolver, "trustResolver cannot be null");
		this.trustResolver = trustResolver;
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
