/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.server.authorization.web;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ErrorAuthenticationFailureHandler;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2TokenRevocationAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A {@code Filter} for the OAuth 2.0 Token Revocation endpoint.
 *
 * @author Vivek Babu
 * @author Joe Grandja
 * @author Arfat Chaus
 * @since 0.0.3
 * @see OAuth2TokenRevocationAuthenticationProvider
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7009#section-2">Section 2
 * Token Revocation</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7009#section-2.1">Section
 * 2.1 Revocation Request</a>
 */
public final class OAuth2TokenRevocationEndpointFilter extends OncePerRequestFilter {

	/**
	 * The default endpoint {@code URI} for token revocation requests.
	 */
	private static final String DEFAULT_TOKEN_REVOCATION_ENDPOINT_URI = "/oauth2/revoke";

	private final AuthenticationManager authenticationManager;

	private final RequestMatcher tokenRevocationEndpointMatcher;

	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

	private AuthenticationConverter authenticationConverter;

	private AuthenticationSuccessHandler authenticationSuccessHandler = this::sendRevocationSuccessResponse;

	private AuthenticationFailureHandler authenticationFailureHandler = new OAuth2ErrorAuthenticationFailureHandler();

	/**
	 * Constructs an {@code OAuth2TokenRevocationEndpointFilter} using the provided
	 * parameters.
	 * @param authenticationManager the authentication manager
	 */
	public OAuth2TokenRevocationEndpointFilter(AuthenticationManager authenticationManager) {
		this(authenticationManager, DEFAULT_TOKEN_REVOCATION_ENDPOINT_URI);
	}

	/**
	 * Constructs an {@code OAuth2TokenRevocationEndpointFilter} using the provided
	 * parameters.
	 * @param authenticationManager the authentication manager
	 * @param tokenRevocationEndpointUri the endpoint {@code URI} for token revocation
	 * requests
	 */
	public OAuth2TokenRevocationEndpointFilter(AuthenticationManager authenticationManager,
			String tokenRevocationEndpointUri) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.hasText(tokenRevocationEndpointUri, "tokenRevocationEndpointUri cannot be empty");
		this.authenticationManager = authenticationManager;
		this.tokenRevocationEndpointMatcher = PathPatternRequestMatcher.withDefaults()
			.matcher(HttpMethod.POST, tokenRevocationEndpointUri);
		this.authenticationConverter = new OAuth2TokenRevocationAuthenticationConverter();
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.tokenRevocationEndpointMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		try {
			Authentication tokenRevocationAuthentication = this.authenticationConverter.convert(request);
			if (tokenRevocationAuthentication instanceof AbstractAuthenticationToken authenticationToken) {
				authenticationToken.setDetails(this.authenticationDetailsSource.buildDetails(request));
			}

			Authentication tokenRevocationAuthenticationResult = this.authenticationManager
				.authenticate(tokenRevocationAuthentication);
			this.authenticationSuccessHandler.onAuthenticationSuccess(request, response,
					tokenRevocationAuthenticationResult);
		}
		catch (OAuth2AuthenticationException ex) {
			SecurityContextHolder.clearContext();
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Token revocation request failed: %s", ex.getError()), ex);
			}
			this.authenticationFailureHandler.onAuthenticationFailure(request, response, ex);
		}
	}

	/**
	 * Sets the {@link AuthenticationDetailsSource} used for building an authentication
	 * details instance from {@link HttpServletRequest}.
	 * @param authenticationDetailsSource the {@link AuthenticationDetailsSource} used for
	 * building an authentication details instance from {@link HttpServletRequest}
	 * @since 1.4
	 */
	public void setAuthenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		Assert.notNull(authenticationDetailsSource, "authenticationDetailsSource cannot be null");
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	/**
	 * Sets the {@link AuthenticationConverter} used when attempting to extract a Revoke
	 * Token Request from {@link HttpServletRequest} to an instance of
	 * {@link OAuth2TokenRevocationAuthenticationToken} used for authenticating the
	 * request.
	 * @param authenticationConverter the {@link AuthenticationConverter} used when
	 * attempting to extract a Revoke Token Request from {@link HttpServletRequest}
	 * @since 0.2.2
	 */
	public void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an
	 * {@link OAuth2TokenRevocationAuthenticationToken}.
	 * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler} used
	 * for handling an {@link OAuth2TokenRevocationAuthenticationToken}
	 * @since 0.2.2
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
	 * @since 0.2.2
	 */
	public void setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
		Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
		this.authenticationFailureHandler = authenticationFailureHandler;
	}

	private void sendRevocationSuccessResponse(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) {
		response.setStatus(HttpStatus.OK.value());
	}

}
