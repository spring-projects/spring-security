/*
 * Copyright 2002-2016 the original author or authors.
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

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
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
	// ~ Static fields/initializers
	// =====================================================================================

	static final String FILTER_APPLIED = "__spring_security_session_mgmt_filter_applied";

	// ~ Instance fields
	// ================================================================================================

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
		Assert.notNull(securityContextRepository,
				"SecurityContextRepository cannot be null");
		Assert.notNull(sessionStrategy, "SessionAuthenticationStrategy cannot be null");
		this.securityContextRepository = securityContextRepository;
		this.sessionAuthenticationStrategy = sessionStrategy;
	}

	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		if (request.getAttribute(FILTER_APPLIED) != null) {
			chain.doFilter(request, response);
			return;
		}

		request.setAttribute(FILTER_APPLIED, Boolean.TRUE);

		if (!securityContextRepository.containsContext(request)) {
			Authentication authentication = SecurityContextHolder.getContext()
					.getAuthentication();

			if (authentication != null && !trustResolver.isAnonymous(authentication)) {
				// The user has been authenticated during the current request, so call the
				// session strategy
				try {
					sessionAuthenticationStrategy.onAuthentication(authentication,
							request, response);
				}
				catch (SessionAuthenticationException e) {
					// The session strategy can reject the authentication
					logger.debug(
							"SessionAuthenticationStrategy rejected the authentication object",
							e);
					SecurityContextHolder.clearContext();
					failureHandler.onAuthenticationFailure(request, response, e);

					return;
				}
				// Eagerly save the security context to make it available for any possible
				// re-entrant
				// requests which may occur before the current request completes.
				// SEC-1396.
				securityContextRepository.saveContext(SecurityContextHolder.getContext(),
						request, response);
			}
			else {
				// No security context or authentication present. Check for a session
				// timeout
				if (request.getRequestedSessionId() != null
						&& !request.isRequestedSessionIdValid()) {
					if (logger.isDebugEnabled()) {
						logger.debug("Requested session ID "
								+ request.getRequestedSessionId() + " is invalid.");
					}

					if (invalidSessionStrategy != null) {
						invalidSessionStrategy
								.onInvalidSessionDetected(request, response);
						return;
					}
				}
			}
		}

		chain.doFilter(request, response);
	}

	/**
	 * Sets the strategy which will be invoked instead of allowing the filter chain to
	 * prceed, if the user agent requests an invalid session Id. If the property is not
	 * set, no action will be taken.
	 *
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
	public void setAuthenticationFailureHandler(
			AuthenticationFailureHandler failureHandler) {
		Assert.notNull(failureHandler, "failureHandler cannot be null");
		this.failureHandler = failureHandler;
	}

	/**
	 * Sets the {@link AuthenticationTrustResolver} to be used. The default is
	 * {@link AuthenticationTrustResolverImpl}.
	 *
	 * @param trustResolver the {@link AuthenticationTrustResolver} to use. Cannot be
	 * null.
	 */
	public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
		Assert.notNull(trustResolver, "trustResolver cannot be null");
		this.trustResolver = trustResolver;
	}
}
