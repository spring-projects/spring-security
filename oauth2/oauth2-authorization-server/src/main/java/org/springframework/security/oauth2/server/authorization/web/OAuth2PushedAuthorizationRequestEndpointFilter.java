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
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.ResolvableType;
import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.SmartHttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2PushedAuthorizationRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2PushedAuthorizationRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeRequestAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2ErrorAuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A {@code Filter} for the OAuth 2.0 Pushed Authorization Request endpoint, which handles
 * the processing of the OAuth 2.0 Pushed Authorization Request.
 *
 * @author Joe Grandja
 * @author Andrey Litvitski
 * @since 7.0
 * @see AuthenticationManager
 * @see OAuth2PushedAuthorizationRequestAuthenticationProvider
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc9126#name-pushed-authorization-reques">Section
 * 2. Pushed Authorization Request Endpoint</a>
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc9126#section-2.1">Section 2.1 Pushed
 * Authorization Request</a>
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc9126#section-2.2">Section 2.2 Pushed
 * Authorization Response</a>
 */
public final class OAuth2PushedAuthorizationRequestEndpointFilter extends OncePerRequestFilter {

	/**
	 * The default endpoint {@code URI} for pushed authorization requests.
	 */
	private static final String DEFAULT_PUSHED_AUTHORIZATION_REQUEST_ENDPOINT_URI = "/oauth2/par";

	private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<>() {
	};

	private static final SmartHttpMessageConverter<Object> JSON_MESSAGE_CONVERTER = HttpMessageConverters
		.getJsonMessageConverter();

	private final AuthenticationManager authenticationManager;

	private final RequestMatcher pushedAuthorizationRequestEndpointMatcher;

	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

	private AuthenticationConverter authenticationConverter;

	private AuthenticationSuccessHandler authenticationSuccessHandler = this::sendPushedAuthorizationResponse;

	private AuthenticationFailureHandler authenticationFailureHandler = new OAuth2ErrorAuthenticationFailureHandler();

	/**
	 * Constructs an {@code OAuth2PushedAuthorizationRequestEndpointFilter} using the
	 * provided parameters.
	 * @param authenticationManager the authentication manager
	 */
	public OAuth2PushedAuthorizationRequestEndpointFilter(AuthenticationManager authenticationManager) {
		this(authenticationManager, DEFAULT_PUSHED_AUTHORIZATION_REQUEST_ENDPOINT_URI);
	}

	/**
	 * Constructs an {@code OAuth2PushedAuthorizationRequestEndpointFilter} using the
	 * provided parameters.
	 * @param authenticationManager the authentication manager
	 * @param pushedAuthorizationRequestEndpointUri the endpoint {@code URI} for pushed
	 * authorization requests
	 */
	public OAuth2PushedAuthorizationRequestEndpointFilter(AuthenticationManager authenticationManager,
			String pushedAuthorizationRequestEndpointUri) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.hasText(pushedAuthorizationRequestEndpointUri, "pushedAuthorizationRequestEndpointUri cannot be empty");
		this.authenticationManager = authenticationManager;
		this.pushedAuthorizationRequestEndpointMatcher = PathPatternRequestMatcher.withDefaults()
			.matcher(HttpMethod.POST, pushedAuthorizationRequestEndpointUri);
		this.authenticationConverter = new OAuth2AuthorizationCodeRequestAuthenticationConverter();
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.pushedAuthorizationRequestEndpointMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		try {
			Authentication pushedAuthorizationRequestAuthentication = this.authenticationConverter.convert(request);
			if (pushedAuthorizationRequestAuthentication instanceof AbstractAuthenticationToken) {
				((AbstractAuthenticationToken) pushedAuthorizationRequestAuthentication)
					.setDetails(this.authenticationDetailsSource.buildDetails(request));
			}
			Authentication pushedAuthorizationRequestAuthenticationResult = this.authenticationManager
				.authenticate(pushedAuthorizationRequestAuthentication);

			this.authenticationSuccessHandler.onAuthenticationSuccess(request, response,
					pushedAuthorizationRequestAuthenticationResult);

		}
		catch (OAuth2AuthenticationException ex) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Pushed authorization request failed: %s", ex.getError()), ex);
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
	 * Sets the {@link AuthenticationConverter} used when attempting to extract a Pushed
	 * Authorization Request from {@link HttpServletRequest} to an instance of
	 * {@link OAuth2PushedAuthorizationRequestAuthenticationToken} used for authenticating
	 * the request.
	 * @param authenticationConverter the {@link AuthenticationConverter} used when
	 * attempting to extract a Pushed Authorization Request from
	 * {@link HttpServletRequest}
	 */
	public void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}

	/**
	 * Sets the {@link AuthenticationSuccessHandler} used for handling an
	 * {@link OAuth2PushedAuthorizationRequestAuthenticationToken} and returning the
	 * Pushed Authorization Response.
	 * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler} used
	 * for handling an {@link OAuth2PushedAuthorizationRequestAuthenticationToken}
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

	private void sendPushedAuthorizationResponse(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException {

		OAuth2PushedAuthorizationRequestAuthenticationToken pushedAuthorizationRequestAuthentication = (OAuth2PushedAuthorizationRequestAuthenticationToken) authentication;

		Map<String, Object> pushedAuthorizationResponse = new LinkedHashMap<>();
		pushedAuthorizationResponse.put(OAuth2ParameterNames.REQUEST_URI,
				pushedAuthorizationRequestAuthentication.getRequestUri());
		long expiresIn = ChronoUnit.SECONDS.between(Instant.now(),
				pushedAuthorizationRequestAuthentication.getRequestUriExpiresAt());
		pushedAuthorizationResponse.put(OAuth2ParameterNames.EXPIRES_IN, expiresIn);

		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		httpResponse.setStatusCode(HttpStatus.CREATED);

		JSON_MESSAGE_CONVERTER.write(pushedAuthorizationResponse, ResolvableType.forType(STRING_OBJECT_MAP.getType()),
				MediaType.APPLICATION_JSON, httpResponse, null);
	}

}
