/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.saml2.provider.service.web.authentication.logout;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A filter for handling logout requests in the form of a &lt;saml2:LogoutRequest&gt; sent
 * from the asserting party.
 *
 * @author Josh Cummings
 * @since 5.5
 */
public final class Saml2LogoutRequestFilter extends OncePerRequestFilter {

	private static final String DEFAULT_LOGOUT_ENDPOINT = "/logout/saml2/slo";

	private RequestMatcher logoutRequestMatcher = new AntPathRequestMatcher(DEFAULT_LOGOUT_ENDPOINT);

	private final LogoutHandler logoutHandler;

	private final LogoutSuccessHandler logoutSuccessHandler;

	/**
	 * Constructs a {@link Saml2LogoutResponseFilter} for accepting SAML 2.0 Logout
	 * Requests from the asserting party
	 * @param logoutSuccessHandler the success handler to be run after the logout request
	 * passes validation and other logout operations succeed. This success handler will
	 * typically be one that issues a SAML 2.0 Logout Response to the asserting party,
	 * like {@link Saml2LogoutResponseSuccessHandler}
	 * @param logoutHandler the handler for handling the logout request, may be a
	 * {@link org.springframework.security.web.authentication.logout.CompositeLogoutHandler}
	 * that handles other logout concerns
	 */
	public Saml2LogoutRequestFilter(LogoutSuccessHandler logoutSuccessHandler, LogoutHandler logoutHandler) {
		this.logoutSuccessHandler = logoutSuccessHandler;
		this.logoutHandler = logoutHandler;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {

		if (!this.logoutRequestMatcher.matches(request)) {
			chain.doFilter(request, response);
			return;
		}

		if (request.getParameter("SAMLRequest") == null) {
			chain.doFilter(request, response);
			return;
		}

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		this.logoutHandler.logout(request, response, authentication);
		this.logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
	}

	public void setLogoutRequestMatcher(RequestMatcher logoutRequestMatcher) {
		Assert.notNull(logoutRequestMatcher, "logoutRequestMatcher cannot be null");
		this.logoutRequestMatcher = logoutRequestMatcher;
	}

}
