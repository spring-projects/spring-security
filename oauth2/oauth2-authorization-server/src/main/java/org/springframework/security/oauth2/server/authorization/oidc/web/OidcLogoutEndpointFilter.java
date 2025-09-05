/*
 * Copyright 2020-2025 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.oidc.web;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.oidc.web.authentication.OidcLogoutAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.oidc.web.authentication.OidcLogoutAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A {@code Filter} that processes OpenID Connect 1.0 RP-Initiated Logout Requests.
 *
 * @author Joe Grandja
 * @since 1.1
 * @see OidcLogoutAuthenticationConverter
 * @see OidcLogoutAuthenticationSuccessHandler
 * @see OidcLogoutAuthenticationProvider
 * @see <a href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout">2.
 * RP-Initiated Logout</a>
 */
public final class OidcLogoutEndpointFilter extends OncePerRequestFilter {

	/**
	 * The default endpoint {@code URI} for OpenID Connect 1.0 RP-Initiated Logout
	 * Requests.
	 */
	private static final String DEFAULT_OIDC_LOGOUT_ENDPOINT_URI = "/connect/logout";

	private final AuthenticationManager authenticationManager;

	private final RequestMatcher logoutEndpointMatcher;

	private AuthenticationConverter authenticationConverter;

	private AuthenticationSuccessHandler authenticationSuccessHandler = new OidcLogoutAuthenticationSuccessHandler();

	private AuthenticationFailureHandler authenticationFailureHandler = this::sendErrorResponse;

	/**
	 * Constructs an {@code OidcLogoutEndpointFilter} using the provided parameters.
	 * @param authenticationManager the authentication manager
	 */
	public OidcLogoutEndpointFilter(AuthenticationManager authenticationManager) {
		this(authenticationManager, DEFAULT_OIDC_LOGOUT_ENDPOINT_URI);
	}

	/**
	 * Constructs an {@code OidcLogoutEndpointFilter} using the provided parameters.
	 * @param authenticationManager the authentication manager
	 * @param logoutEndpointUri the endpoint {@code URI} for OpenID Connect 1.0
	 * RP-Initiated Logout Requests
	 */
	public OidcLogoutEndpointFilter(AuthenticationManager authenticationManager, String logoutEndpointUri) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.hasText(logoutEndpointUri, "logoutEndpointUri cannot be empty");
		this.authenticationManager = authenticationManager;
		this.logoutEndpointMatcher = new OrRequestMatcher(
				PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET, logoutEndpointUri),
				PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, logoutEndpointUri));
		this.authenticationConverter = new OidcLogoutAuthenticationConverter();
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.logoutEndpointMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		try {
			Authentication oidcLogoutAuthentication = this.authenticationConverter.convert(request);

			Authentication oidcLogoutAuthenticationResult = this.authenticationManager
				.authenticate(oidcLogoutAuthentication);

			this.authenticationSuccessHandler.onAuthenticationSuccess(request, response,
					oidcLogoutAuthenticationResult);
		}
		catch (OAuth2AuthenticationException ex) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Logout request failed: %s", ex.getError()), ex);
			}
			this.authenticationFailureHandler.onAuthenticationFailure(request, response, ex);
		}
		catch (Exception ex) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
					"OpenID Connect 1.0 RP-Initiated Logout Error: " + ex.getMessage(),
					"https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ValidationAndErrorHandling");
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(error, ex);
			}
			this.authenticationFailureHandler.onAuthenticationFailure(request, response,
					new OAuth2AuthenticationException(error));
		}
	}

	/**
	 * Sets the {@link AuthenticationConverter} used when attempting to extract a Logout
	 * Request from {@link HttpServletRequest} to an instance of
	 * {@link OidcLogoutAuthenticationToken} used for authenticating the request.
	 * @param authenticationConverter the {@link AuthenticationConverter} used when
	 * attempting to extract a Logout Request from {@link HttpServletRequest}
	 */
	public void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an
	 * {@link OidcLogoutAuthenticationToken} and performing the logout.
	 * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler} used
	 * for handling an {@link OidcLogoutAuthenticationToken}
	 */
	public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
		Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
		this.authenticationSuccessHandler = authenticationSuccessHandler;
	}

	/**
	 * Sets the {@link AuthenticationFailureHandler} used for handling an
	 * {@link OAuth2AuthenticationException} and returning the {@link OAuth2Error Error
	 * Response}.
	 * @param authenticationFailureHandler the {@link AuthenticationFailureHandler} used
	 * for handling an {@link OAuth2AuthenticationException}
	 */
	public void setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
		Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
		this.authenticationFailureHandler = authenticationFailureHandler;
	}

	private void sendErrorResponse(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException {

		OAuth2Error error = ((OAuth2AuthenticationException) exception).getError();
		response.sendError(HttpStatus.BAD_REQUEST.value(), error.toString());
	}

}
