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

package org.springframework.security.config.annotation.web.configurers.oauth2.client;

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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A filter for the Client-side OIDC Back-Channel Logout endpoint
 *
 * @author Josh Cummings
 * @since 6.2
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-backchannel-1_0.html">OIDC Back-Channel Logout
 * Spec</a>
 */
class OidcBackChannelLogoutFilter extends OncePerRequestFilter {

	private final Log logger = LogFactory.getLog(getClass());

	private final AuthenticationConverter authenticationConverter;

	private final AuthenticationManager authenticationManager;

	private final OAuth2ErrorHttpMessageConverter errorHttpMessageConverter = new OAuth2ErrorHttpMessageConverter();

	private final LogoutHandler logoutHandler;

	/**
	 * Construct an {@link OidcBackChannelLogoutFilter}
	 * @param authenticationConverter the {@link AuthenticationConverter} for deriving
	 * Logout Token authentication
	 * @param authenticationManager the {@link AuthenticationManager} for authenticating
	 * Logout Tokens
	 */
	OidcBackChannelLogoutFilter(AuthenticationConverter authenticationConverter,
			AuthenticationManager authenticationManager, LogoutHandler logoutHandler) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.notNull(logoutHandler, "logoutHandler cannot be null");
		this.authenticationConverter = authenticationConverter;
		this.authenticationManager = authenticationManager;
		this.logoutHandler = logoutHandler;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		Authentication token;
		try {
			token = this.authenticationConverter.convert(request);
		}
		catch (AuthenticationServiceException ex) {
			this.logger.debug("Failed to process OIDC Back-Channel Logout", ex);
			throw ex;
		}
		catch (AuthenticationException ex) {
			handleAuthenticationFailure(response, ex);
			return;
		}
		if (token == null) {
			chain.doFilter(request, response);
			return;
		}
		Authentication authentication;
		try {
			authentication = this.authenticationManager.authenticate(token);
		}
		catch (AuthenticationServiceException ex) {
			this.logger.debug("Failed to process OIDC Back-Channel Logout", ex);
			throw ex;
		}
		catch (AuthenticationException ex) {
			handleAuthenticationFailure(response, ex);
			return;
		}
		this.logoutHandler.logout(request, response, authentication);
	}

	private void handleAuthenticationFailure(HttpServletResponse response, Exception ex) throws IOException {
		this.logger.debug("Failed to process OIDC Back-Channel Logout", ex);
		response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
		this.errorHttpMessageConverter.write(oauth2Error(ex), null, new ServletServerHttpResponse(response));
	}

	private OAuth2Error oauth2Error(Exception ex) {
		if (ex instanceof OAuth2AuthenticationException oauth2) {
			return oauth2.getError();
		}
		return new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, ex.getMessage(),
				"https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation");
	}

}
