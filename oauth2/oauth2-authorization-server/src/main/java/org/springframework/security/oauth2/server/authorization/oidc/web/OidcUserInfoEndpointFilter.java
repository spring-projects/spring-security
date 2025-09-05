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
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.oidc.http.converter.OidcUserInfoHttpMessageConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A {@code Filter} that processes OpenID Connect 1.0 UserInfo Requests.
 *
 * @author Ido Salomon
 * @author Steve Riesenberg
 * @author Daniel Garnier-Moiroux
 * @since 0.2.1
 * @see OidcUserInfo
 * @see OidcUserInfoAuthenticationProvider
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">5.3.
 * UserInfo Endpoint</a>
 */
public final class OidcUserInfoEndpointFilter extends OncePerRequestFilter {

	/**
	 * The default endpoint {@code URI} for OpenID Connect 1.0 UserInfo Requests.
	 */
	private static final String DEFAULT_OIDC_USER_INFO_ENDPOINT_URI = "/userinfo";

	private final AuthenticationManager authenticationManager;

	private final RequestMatcher userInfoEndpointMatcher;

	private final HttpMessageConverter<OidcUserInfo> userInfoHttpMessageConverter = new OidcUserInfoHttpMessageConverter();

	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter = new OAuth2ErrorHttpMessageConverter();

	private AuthenticationConverter authenticationConverter = this::createAuthentication;

	private AuthenticationSuccessHandler authenticationSuccessHandler = this::sendUserInfoResponse;

	private AuthenticationFailureHandler authenticationFailureHandler = this::sendErrorResponse;

	/**
	 * Constructs an {@code OidcUserInfoEndpointFilter} using the provided parameters.
	 * @param authenticationManager the authentication manager
	 */
	public OidcUserInfoEndpointFilter(AuthenticationManager authenticationManager) {
		this(authenticationManager, DEFAULT_OIDC_USER_INFO_ENDPOINT_URI);
	}

	/**
	 * Constructs an {@code OidcUserInfoEndpointFilter} using the provided parameters.
	 * @param authenticationManager the authentication manager
	 * @param userInfoEndpointUri the endpoint {@code URI} for OpenID Connect 1.0 UserInfo
	 * Requests
	 */
	public OidcUserInfoEndpointFilter(AuthenticationManager authenticationManager, String userInfoEndpointUri) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.hasText(userInfoEndpointUri, "userInfoEndpointUri cannot be empty");
		this.authenticationManager = authenticationManager;
		this.userInfoEndpointMatcher = new OrRequestMatcher(
				PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET, userInfoEndpointUri),
				PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, userInfoEndpointUri));
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.userInfoEndpointMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		try {
			Authentication userInfoAuthentication = this.authenticationConverter.convert(request);

			Authentication userInfoAuthenticationResult = this.authenticationManager
				.authenticate(userInfoAuthentication);

			this.authenticationSuccessHandler.onAuthenticationSuccess(request, response, userInfoAuthenticationResult);
		}
		catch (OAuth2AuthenticationException ex) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("User info request failed: %s", ex.getError()), ex);
			}
			this.authenticationFailureHandler.onAuthenticationFailure(request, response, ex);
		}
		catch (Exception ex) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
					"OpenID Connect 1.0 UserInfo Error: " + ex.getMessage(),
					"https://openid.net/specs/openid-connect-core-1_0.html#UserInfoError");
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(error.getDescription(), ex);
			}
			this.authenticationFailureHandler.onAuthenticationFailure(request, response,
					new OAuth2AuthenticationException(error));
		}
		finally {
			SecurityContextHolder.clearContext();
		}
	}

	/**
	 * Sets the {@link AuthenticationConverter} used when attempting to extract an
	 * UserInfo Request from {@link HttpServletRequest} to an instance of
	 * {@link OidcUserInfoAuthenticationToken} used for authenticating the request.
	 * @param authenticationConverter the {@link AuthenticationConverter} used when
	 * attempting to extract an UserInfo Request from {@link HttpServletRequest}
	 * @since 0.4.0
	 */
	public void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an
	 * {@link OidcUserInfoAuthenticationToken} and returning the {@link OidcUserInfo
	 * UserInfo Response}.
	 * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler} used
	 * for handling an {@link OidcUserInfoAuthenticationToken}
	 * @since 0.4.0
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
	 * @since 0.4.0
	 */
	public void setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
		Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
		this.authenticationFailureHandler = authenticationFailureHandler;
	}

	private Authentication createAuthentication(HttpServletRequest request) {
		Authentication principal = SecurityContextHolder.getContext().getAuthentication();
		return new OidcUserInfoAuthenticationToken(principal);
	}

	private void sendUserInfoResponse(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException {
		OidcUserInfoAuthenticationToken userInfoAuthenticationToken = (OidcUserInfoAuthenticationToken) authentication;
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		this.userInfoHttpMessageConverter.write(userInfoAuthenticationToken.getUserInfo(), null, httpResponse);
	}

	private void sendErrorResponse(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authenticationException) throws IOException {
		OAuth2Error error = ((OAuth2AuthenticationException) authenticationException).getError();
		HttpStatus httpStatus = HttpStatus.BAD_REQUEST;
		if (error.getErrorCode().equals(OAuth2ErrorCodes.INVALID_TOKEN)) {
			httpStatus = HttpStatus.UNAUTHORIZED;
		}
		else if (error.getErrorCode().equals(OAuth2ErrorCodes.INSUFFICIENT_SCOPE)) {
			httpStatus = HttpStatus.FORBIDDEN;
		}
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		httpResponse.setStatusCode(httpStatus);
		this.errorHttpResponseConverter.write(error, null, httpResponse);
	}

}
