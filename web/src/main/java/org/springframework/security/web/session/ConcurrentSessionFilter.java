/*
 * Copyright 2002-2019 the original author or authors.
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
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Filter required by concurrent session handling package.
 * <p>
 * This filter performs two functions. First, it calls
 * {@link org.springframework.security.core.session.SessionRegistry#refreshLastRequest(String)}
 * for each request so that registered sessions always have a correct "last update"
 * date/time. Second, it retrieves a
 * {@link org.springframework.security.core.session.SessionInformation} from the
 * <code>SessionRegistry</code> for each request and checks if the session has been marked
 * as expired. If it has been marked as expired, the configured logout handlers will be
 * called (as happens with
 * {@link org.springframework.security.web.authentication.logout.LogoutFilter}), typically
 * to invalidate the session. To handle the expired session a call to the
 * {@link SessionInformationExpiredStrategy} is made. The session invalidation will cause
 * an {@link org.springframework.security.web.session.HttpSessionDestroyedEvent} to be
 * published via the
 * {@link org.springframework.security.web.session.HttpSessionEventPublisher} registered
 * in <code>web.xml</code>.
 * </p>
 *
 * @author Ben Alex
 * @author Eddú Meléndez
 * @author Marten Deinum
 * @author Onur Kagan Ozcan
 */
public class ConcurrentSessionFilter extends GenericFilterBean {

	private final SessionRegistry sessionRegistry;

	private String expiredUrl;

	private RedirectStrategy redirectStrategy;

	private LogoutHandler handlers = new CompositeLogoutHandler(new SecurityContextLogoutHandler());

	private SessionInformationExpiredStrategy sessionInformationExpiredStrategy;

	public ConcurrentSessionFilter(SessionRegistry sessionRegistry) {
		Assert.notNull(sessionRegistry, "SessionRegistry required");
		this.sessionRegistry = sessionRegistry;
		this.sessionInformationExpiredStrategy = new ResponseBodySessionInformationExpiredStrategy();
	}

	/**
	 * Creates a new instance
	 * @param sessionRegistry the SessionRegistry to use
	 * @param expiredUrl the URL to redirect to
	 * @deprecated use
	 * {@link #ConcurrentSessionFilter(SessionRegistry, SessionInformationExpiredStrategy)}
	 * with {@link SimpleRedirectSessionInformationExpiredStrategy} instead.
	 */
	@Deprecated
	public ConcurrentSessionFilter(SessionRegistry sessionRegistry, String expiredUrl) {
		Assert.notNull(sessionRegistry, "SessionRegistry required");
		Assert.isTrue(expiredUrl == null || UrlUtils.isValidRedirectUrl(expiredUrl),
				() -> expiredUrl + " isn't a valid redirect URL");
		this.expiredUrl = expiredUrl;
		this.sessionRegistry = sessionRegistry;
		this.sessionInformationExpiredStrategy = (event) -> {
			HttpServletRequest request = event.getRequest();
			HttpServletResponse response = event.getResponse();
			SessionInformation info = event.getSessionInformation();

			this.redirectStrategy.sendRedirect(request, response, determineExpiredUrl(request, info));
		};
	}

	public ConcurrentSessionFilter(SessionRegistry sessionRegistry,
			SessionInformationExpiredStrategy sessionInformationExpiredStrategy) {
		Assert.notNull(sessionRegistry, "sessionRegistry required");
		Assert.notNull(sessionInformationExpiredStrategy, "sessionInformationExpiredStrategy cannot be null");
		this.sessionRegistry = sessionRegistry;
		this.sessionInformationExpiredStrategy = sessionInformationExpiredStrategy;
	}

	@Override
	public void afterPropertiesSet() {
		Assert.notNull(this.sessionRegistry, "SessionRegistry required");
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		HttpSession session = request.getSession(false);

		if (session != null) {
			SessionInformation info = this.sessionRegistry.getSessionInformation(session.getId());

			if (info != null) {
				if (info.isExpired()) {
					// Expired - abort processing
					if (this.logger.isDebugEnabled()) {
						this.logger.debug("Requested session ID " + request.getRequestedSessionId() + " has expired.");
					}
					doLogout(request, response);

					this.sessionInformationExpiredStrategy
							.onExpiredSessionDetected(new SessionInformationExpiredEvent(info, request, response));
					return;
				}
				else {
					// Non-expired - update last request date/time
					this.sessionRegistry.refreshLastRequest(info.getSessionId());
				}
			}
		}

		chain.doFilter(request, response);
	}

	/**
	 * Determine the URL for expiration
	 * @param request the HttpServletRequest
	 * @param info the {@link SessionInformation}
	 * @return the URL for expiration
	 * @deprecated Use
	 * {@link #ConcurrentSessionFilter(SessionRegistry, SessionInformationExpiredStrategy)}
	 * instead.
	 */
	@Deprecated
	protected String determineExpiredUrl(HttpServletRequest request, SessionInformation info) {
		return this.expiredUrl;
	}

	private void doLogout(HttpServletRequest request, HttpServletResponse response) {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();

		this.handlers.logout(request, response, auth);
	}

	public void setLogoutHandlers(LogoutHandler[] handlers) {
		this.handlers = new CompositeLogoutHandler(handlers);
	}

	/**
	 * Set list of {@link LogoutHandler}
	 * @param handlers list of {@link LogoutHandler}
	 * @since 5.2.0
	 */
	public void setLogoutHandlers(List<LogoutHandler> handlers) {
		this.handlers = new CompositeLogoutHandler(handlers);
	}

	/**
	 * Sets the {@link RedirectStrategy} used with
	 * {@link #ConcurrentSessionFilter(SessionRegistry, String)}
	 * @param redirectStrategy the {@link RedirectStrategy} to use
	 * @deprecated use
	 * {@link #ConcurrentSessionFilter(SessionRegistry, SessionInformationExpiredStrategy)}
	 * instead.
	 */
	@Deprecated
	public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
		this.redirectStrategy = redirectStrategy;
	}

	/**
	 * A {@link SessionInformationExpiredStrategy} that writes an error message to the
	 * response body.
	 *
	 * @author Rob Winch
	 * @since 4.2
	 */
	private static final class ResponseBodySessionInformationExpiredStrategy
			implements SessionInformationExpiredStrategy {

		@Override
		public void onExpiredSessionDetected(SessionInformationExpiredEvent event) throws IOException {
			HttpServletResponse response = event.getResponse();
			response.getWriter().print("This session has been expired (possibly due to multiple concurrent "
					+ "logins being attempted as the same user).");
			response.flushBuffer();
		}

	}

}
