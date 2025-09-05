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
package org.springframework.security.oauth2.server.authorization.web;

import java.io.IOException;
import java.util.Arrays;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AccessTokenResponseAuthenticationSuccessHandler;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ClientCredentialsAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2DeviceCodeAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ErrorAuthenticationFailureHandler;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2RefreshTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2TokenExchangeAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A {@code Filter} for the OAuth 2.0 Token endpoint, which handles the processing of an
 * OAuth 2.0 Authorization Grant.
 *
 * <p>
 * It converts the OAuth 2.0 Authorization Grant request to an {@link Authentication},
 * which is then authenticated by the {@link AuthenticationManager}. If the authentication
 * succeeds, the {@link AuthenticationManager} returns an
 * {@link OAuth2AccessTokenAuthenticationToken}, which is returned in the OAuth 2.0 Access
 * Token response. In case of any error, an {@link OAuth2Error} is returned in the OAuth
 * 2.0 Error response.
 *
 * <p>
 * By default, this {@code Filter} responds to authorization grant requests at the
 * {@code URI} {@code /oauth2/token} and {@code HttpMethod} {@code POST}.
 *
 * <p>
 * The default endpoint {@code URI} {@code /oauth2/token} may be overridden via the
 * constructor {@link #OAuth2TokenEndpointFilter(AuthenticationManager, String)}.
 *
 * @author Joe Grandja
 * @author Madhu Bhat
 * @author Daniel Garnier-Moiroux
 * @author Dmitriy Dubson
 * @since 0.0.1
 * @see AuthenticationManager
 * @see OAuth2AuthorizationCodeAuthenticationProvider
 * @see OAuth2RefreshTokenAuthenticationProvider
 * @see OAuth2ClientCredentialsAuthenticationProvider
 * @see OAuth2DeviceCodeAuthenticationProvider
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-3.2">Section
 * 3.2 Token Endpoint</a>
 */
public final class OAuth2TokenEndpointFilter extends OncePerRequestFilter {

	/**
	 * The default endpoint {@code URI} for access token requests.
	 */
	private static final String DEFAULT_TOKEN_ENDPOINT_URI = "/oauth2/token";

	private static final String DEFAULT_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

	private final AuthenticationManager authenticationManager;

	private final RequestMatcher tokenEndpointMatcher;

	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

	private AuthenticationConverter authenticationConverter;

	private AuthenticationSuccessHandler authenticationSuccessHandler = new OAuth2AccessTokenResponseAuthenticationSuccessHandler();

	private AuthenticationFailureHandler authenticationFailureHandler = new OAuth2ErrorAuthenticationFailureHandler();

	/**
	 * Constructs an {@code OAuth2TokenEndpointFilter} using the provided parameters.
	 * @param authenticationManager the authentication manager
	 */
	public OAuth2TokenEndpointFilter(AuthenticationManager authenticationManager) {
		this(authenticationManager, DEFAULT_TOKEN_ENDPOINT_URI);
	}

	/**
	 * Constructs an {@code OAuth2TokenEndpointFilter} using the provided parameters.
	 * @param authenticationManager the authentication manager
	 * @param tokenEndpointUri the endpoint {@code URI} for access token requests
	 */
	public OAuth2TokenEndpointFilter(AuthenticationManager authenticationManager, String tokenEndpointUri) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.hasText(tokenEndpointUri, "tokenEndpointUri cannot be empty");
		this.authenticationManager = authenticationManager;
		this.tokenEndpointMatcher = PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, tokenEndpointUri);
		// @formatter:off
		this.authenticationConverter = new DelegatingAuthenticationConverter(
				Arrays.asList(
						new OAuth2AuthorizationCodeAuthenticationConverter(),
						new OAuth2RefreshTokenAuthenticationConverter(),
						new OAuth2ClientCredentialsAuthenticationConverter(),
						new OAuth2DeviceCodeAuthenticationConverter(),
						new OAuth2TokenExchangeAuthenticationConverter())
		);
		// @formatter:on
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.tokenEndpointMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		try {
			String[] grantTypes = request.getParameterValues(OAuth2ParameterNames.GRANT_TYPE);
			if (grantTypes == null || grantTypes.length != 1) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.GRANT_TYPE);
			}

			Authentication authorizationGrantAuthentication = this.authenticationConverter.convert(request);
			if (authorizationGrantAuthentication == null) {
				throwError(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE, OAuth2ParameterNames.GRANT_TYPE);
			}
			if (authorizationGrantAuthentication instanceof AbstractAuthenticationToken authenticationToken) {
				authenticationToken.setDetails(this.authenticationDetailsSource.buildDetails(request));
			}

			OAuth2AccessTokenAuthenticationToken accessTokenAuthentication = (OAuth2AccessTokenAuthenticationToken) this.authenticationManager
				.authenticate(authorizationGrantAuthentication);
			this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, accessTokenAuthentication);
		}
		catch (OAuth2AuthenticationException ex) {
			SecurityContextHolder.clearContext();
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Token request failed: %s", ex.getError()), ex);
			}
			this.authenticationFailureHandler.onAuthenticationFailure(request, response, ex);
		}
	}

	/**
	 * Sets the {@link AuthenticationDetailsSource} used for building an authentication
	 * details instance from {@link HttpServletRequest}.
	 * @param authenticationDetailsSource the {@link AuthenticationDetailsSource} used for
	 * building an authentication details instance from {@link HttpServletRequest}
	 */
	public void setAuthenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		Assert.notNull(authenticationDetailsSource, "authenticationDetailsSource cannot be null");
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	/**
	 * Sets the {@link AuthenticationConverter} used when attempting to extract an Access
	 * Token Request from {@link HttpServletRequest} to an instance of
	 * {@link OAuth2AuthorizationGrantAuthenticationToken} used for authenticating the
	 * authorization grant.
	 * @param authenticationConverter the {@link AuthenticationConverter} used when
	 * attempting to extract an Access Token Request from {@link HttpServletRequest}
	 */
	public void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an
	 * {@link OAuth2AccessTokenAuthenticationToken} and returning the
	 * {@link OAuth2AccessTokenResponse Access Token Response}.
	 * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler} used
	 * for handling an {@link OAuth2AccessTokenAuthenticationToken}
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

	private static void throwError(String errorCode, String parameterName) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, DEFAULT_ERROR_URI);
		throw new OAuth2AuthenticationException(error);
	}

}
