/*
 * Copyright 2020-2024 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.oidc.web.authentication;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcLogoutEndpointFilter;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

/**
 * An implementation of an {@link AuthenticationSuccessHandler} used for handling an
 * {@link OidcLogoutAuthenticationToken} and performing the OpenID Connect 1.0
 * RP-Initiated Logout.
 *
 * @author Joe Grandja
 * @since 1.4
 * @see OidcLogoutEndpointFilter#setAuthenticationSuccessHandler(AuthenticationSuccessHandler)
 * @see LogoutHandler
 */
public final class OidcLogoutAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

	private final Log logger = LogFactory.getLog(getClass());

	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	private final SecurityContextLogoutHandler securityContextLogoutHandler = new SecurityContextLogoutHandler();

	private LogoutHandler logoutHandler = this::performLogout;

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {

		if (!(authentication instanceof OidcLogoutAuthenticationToken)) {
			if (this.logger.isErrorEnabled()) {
				this.logger.error(Authentication.class.getSimpleName() + " must be of type "
						+ OidcLogoutAuthenticationToken.class.getName() + " but was "
						+ authentication.getClass().getName());
			}
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
					"Unable to process the OpenID Connect 1.0 RP-Initiated Logout response.", null);
			throw new OAuth2AuthenticationException(error);
		}

		this.logoutHandler.logout(request, response, authentication);

		sendLogoutRedirect(request, response, authentication);
	}

	/**
	 * Sets the {@link LogoutHandler} used for performing logout.
	 * @param logoutHandler the {@link LogoutHandler} used for performing logout
	 */
	public void setLogoutHandler(LogoutHandler logoutHandler) {
		Assert.notNull(logoutHandler, "logoutHandler cannot be null");
		this.logoutHandler = logoutHandler;
	}

	private void performLogout(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) {
		OidcLogoutAuthenticationToken oidcLogoutAuthentication = (OidcLogoutAuthenticationToken) authentication;

		// Check for active user session
		if (oidcLogoutAuthentication.isPrincipalAuthenticated()) {
			this.securityContextLogoutHandler.logout(request, response,
					(Authentication) oidcLogoutAuthentication.getPrincipal());
		}
	}

	private void sendLogoutRedirect(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException {
		OidcLogoutAuthenticationToken oidcLogoutAuthentication = (OidcLogoutAuthenticationToken) authentication;

		String redirectUri = "/";
		if (oidcLogoutAuthentication.isAuthenticated()
				&& StringUtils.hasText(oidcLogoutAuthentication.getPostLogoutRedirectUri())) {
			// Use the `post_logout_redirect_uri` parameter
			UriComponentsBuilder uriBuilder = UriComponentsBuilder
				.fromUriString(oidcLogoutAuthentication.getPostLogoutRedirectUri());
			if (StringUtils.hasText(oidcLogoutAuthentication.getState())) {
				uriBuilder.queryParam(OAuth2ParameterNames.STATE,
						UriUtils.encode(oidcLogoutAuthentication.getState(), StandardCharsets.UTF_8));
			}
			// build(true) -> Components are explicitly encoded
			redirectUri = uriBuilder.build(true).toUriString();
		}
		this.redirectStrategy.sendRedirect(request, response, redirectUri);
	}

}
