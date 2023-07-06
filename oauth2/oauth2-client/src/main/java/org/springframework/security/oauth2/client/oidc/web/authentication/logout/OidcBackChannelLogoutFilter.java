/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.oauth2.client.oidc.web.authentication.logout;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcBackChannelLogoutAuthenticationToken;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;
import org.springframework.security.oauth2.client.oidc.authentication.session.InMemoryOidcSessionRegistry;
import org.springframework.security.oauth2.client.oidc.authentication.session.OidcSessionRegistration;
import org.springframework.security.oauth2.client.oidc.authentication.session.OidcSessionRegistry;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.web.authentication.logout.BackchannelLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A filter for the Client-side OIDC Back-Channel Logout endpoint
 *
 * @author Josh Cummings
 * @since 6.1
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-backchannel-1_0.html">OIDC Back-Channel Logout
 * Spec</a>
 */
public class OidcBackChannelLogoutFilter extends OncePerRequestFilter {

	private static final String DEFAULT_LOGOUT_URI = "/logout/connect/back-channel/{registrationId}";

	private final Log logger = LogFactory.getLog(getClass());

	private final ClientRegistrationRepository clientRegistrationRepository;

	private final AuthenticationManager authenticationManager;

	private final OAuth2ErrorHttpMessageConverter errorHttpMessageConverter = new OAuth2ErrorHttpMessageConverter();

	private RequestMatcher requestMatcher = new AntPathRequestMatcher(DEFAULT_LOGOUT_URI, "POST");

	private OidcSessionRegistry providerSessionRegistry = new InMemoryOidcSessionRegistry();

	private LogoutHandler logoutHandler = new BackchannelLogoutHandler();

	/**
	 * Construct an {@link OidcBackChannelLogoutFilter}
	 * @param clientRegistrationRepository the {@link ClientRegistrationRepository} for
	 * deriving Logout Token authentication
	 * @param authenticationManager the {@link AuthenticationManager} for authenticating
	 * Logout Tokens
	 */
	public OidcBackChannelLogoutFilter(ClientRegistrationRepository clientRegistrationRepository,
			AuthenticationManager authenticationManager) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authenticationManager = authenticationManager;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		RequestMatcher.MatchResult result = this.requestMatcher.matcher(request);
		if (!result.isMatch()) {
			chain.doFilter(request, response);
			return;
		}
		String registrationId = result.getVariables().get("registrationId");
		ClientRegistration registration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
		if (registration == null) {
			this.logger.debug("Did not process OIDC Back-Channel Logout since no ClientRegistration was found");
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			return;
		}
		String logoutToken = request.getParameter("logout_token");
		if (logoutToken == null) {
			this.logger.debug("Failed to process OIDC Back-Channel Logout since no logout token was found");
			response.sendError(HttpServletResponse.SC_BAD_REQUEST);
			return;
		}
		OidcLogoutToken token;
		try {
			token = authenticate(logoutToken, registration);
		}
		catch (AuthenticationServiceException ex) {
			this.logger.debug("Failed to process OIDC Back-Channel Logout", ex);
			response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, ex.getMessage());
			return;
		}
		catch (AuthenticationException ex) {
			this.logger.debug("Failed to process OIDC Back-Channel Logout", ex);
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, ex.getMessage(),
					"https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation");
			response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
			this.errorHttpMessageConverter.write(error, null, new ServletServerHttpResponse(response));
			return;
		}
		int sessionCount = 0;
		Iterable<OidcSessionRegistration> sessions = this.providerSessionRegistry.deregister(token);
		for (OidcSessionRegistration session : sessions) {
			if (this.logger.isTraceEnabled()) {
				String message = "Logging out session #%d from result set for issuer [%s]";
				this.logger.trace(String.format(message, sessionCount, token.getIssuer()));
			}
			this.logoutHandler.logout(request, response, session.getLogoutAuthenticationToken());
			sessionCount++;
		}
		if (this.logger.isTraceEnabled()) {
			this.logger.trace(String.format("Invalidated all %d linked sessions for issuer [%s]", sessionCount,
					token.getIssuer()));
		}
	}

	private OidcLogoutToken authenticate(String logoutToken, ClientRegistration registration) {
		OidcBackChannelLogoutAuthenticationToken token = new OidcBackChannelLogoutAuthenticationToken(logoutToken,
				registration);
		return (OidcLogoutToken) this.authenticationManager.authenticate(token).getPrincipal();
	}

	/**
	 * The logout endpoint. Defaults to
	 * {@code /logout/connect/back-channel/{registrationId}}.
	 * @param requestMatcher the {@link RequestMatcher} to use
	 */
	public void setRequestMatcher(RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.requestMatcher = requestMatcher;
	}

	/**
	 * The registry for linking Client sessions to OIDC Provider sessions and End Users
	 * @param providerSessionRegistry the {@link OidcSessionRegistry} to use
	 */
	public void setProviderSessionRegistry(OidcSessionRegistry providerSessionRegistry) {
		Assert.notNull(providerSessionRegistry, "providerSessionRegistry cannot be null");
		this.providerSessionRegistry = providerSessionRegistry;
	}

	/**
	 * The strategy for expiring each Client session indicated by the logout request.
	 * Defaults to {@link BackchannelLogoutHandler}.
	 * @param logoutHandler the {@link LogoutHandler} to use
	 */
	public void setLogoutHandler(LogoutHandler logoutHandler) {
		Assert.notNull(logoutHandler, "logoutHandler cannot be null");
		this.logoutHandler = logoutHandler;
	}

}
