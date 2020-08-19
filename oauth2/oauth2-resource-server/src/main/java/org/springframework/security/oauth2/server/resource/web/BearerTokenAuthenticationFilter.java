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

package org.springframework.security.oauth2.server.resource.web;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Authenticates requests that contain an OAuth 2.0
 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
 * Token</a>.
 *
 * This filter should be wired with an {@link AuthenticationManager} that can authenticate
 * a {@link BearerTokenAuthenticationToken}.
 *
 * @author Josh Cummings
 * @author Vedran Pavic
 * @author Joe Grandja
 * @since 5.1
 * @see <a href="https://tools.ietf.org/html/rfc6750" target="_blank">The OAuth 2.0
 * Authorization Framework: Bearer Token Usage</a>
 * @see JwtAuthenticationProvider
 */
public final class BearerTokenAuthenticationFilter extends OncePerRequestFilter {

	private final AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver;

	private AuthenticationEntryPoint authenticationEntryPoint = new BearerTokenAuthenticationEntryPoint();

	private AuthenticationFailureHandler authenticationFailureHandler = (request, response, exception) -> {
		if (exception instanceof AuthenticationServiceException) {
			throw exception;
		}
		this.authenticationEntryPoint.commence(request, response, exception);
	};

	private AuthenticationConverter authenticationConverter = new BearerTokenAuthenticationConverter();

	/**
	 * Construct a {@code BearerTokenAuthenticationFilter} using the provided parameter(s)
	 * @param authenticationManagerResolver
	 */
	public BearerTokenAuthenticationFilter(
			AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver) {
		Assert.notNull(authenticationManagerResolver, "authenticationManagerResolver cannot be null");
		this.authenticationManagerResolver = authenticationManagerResolver;
	}

	/**
	 * Construct a {@code BearerTokenAuthenticationFilter} using the provided parameter(s)
	 * @param authenticationManager
	 */
	public BearerTokenAuthenticationFilter(AuthenticationManager authenticationManager) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		this.authenticationManagerResolver = (request) -> authenticationManager;
	}

	/**
	 * Extract any
	 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
	 * Token</a> from the request and attempt an authentication.
	 * @param request
	 * @param response
	 * @param filterChain
	 * @throws ServletException
	 * @throws IOException
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		Authentication authenticationRequest;
		try {
			authenticationRequest = this.authenticationConverter.convert(request);
		}
		catch (AuthenticationException invalid) {
			this.logger.trace("Sending to authentication entry point since failed to resolve bearer token", invalid);
			this.authenticationEntryPoint.commence(request, response, invalid);
			return;
		}
		if (authenticationRequest == null) {
			this.logger.trace("Did not process request since did not find bearer token");
			filterChain.doFilter(request, response);
			return;
		}

		try {
			AuthenticationManager authenticationManager = this.authenticationManagerResolver.resolve(request);
			Authentication authenticationResult = authenticationManager.authenticate(authenticationRequest);
			SecurityContext context = SecurityContextHolder.createEmptyContext();
			context.setAuthentication(authenticationResult);
			SecurityContextHolder.setContext(context);
			if (this.logger.isDebugEnabled()) {
				this.logger.debug(LogMessage.format("Set SecurityContextHolder to %s", authenticationResult));
			}
			filterChain.doFilter(request, response);
		}
		catch (AuthenticationException failed) {
			SecurityContextHolder.clearContext();
			this.logger.trace("Failed to process authentication request", failed);
			this.authenticationFailureHandler.onAuthenticationFailure(request, response, failed);
		}
	}

	/**
	 * Set the {@link BearerTokenResolver} to use. Defaults to
	 * {@link DefaultBearerTokenResolver}.
	 * @param bearerTokenResolver the {@code BearerTokenResolver} to use
	 * @deprecated Instead, use {@link BearerTokenAuthenticationConverter} explicitly
	 * @see BearerTokenAuthenticationConverter
	 */
	@Deprecated
	public void setBearerTokenResolver(BearerTokenResolver bearerTokenResolver) {
		Assert.notNull(bearerTokenResolver, "bearerTokenResolver cannot be null");
		Assert.isTrue(this.authenticationConverter instanceof BearerTokenAuthenticationConverter,
				"bearerTokenResolver and authenticationConverter cannot both be customized in this filter. "
						+ "Since you've customized the authenticationConverter, "
						+ "please consider configuring the bearerTokenResolver there.");
		((BearerTokenAuthenticationConverter) this.authenticationConverter).setBearerTokenResolver(bearerTokenResolver);
	}

	/**
	 * Set the {@link AuthenticationEntryPoint} to use. Defaults to
	 * {@link BearerTokenAuthenticationEntryPoint}.
	 * @param authenticationEntryPoint the {@code AuthenticationEntryPoint} to use
	 */
	public void setAuthenticationEntryPoint(final AuthenticationEntryPoint authenticationEntryPoint) {
		Assert.notNull(authenticationEntryPoint, "authenticationEntryPoint cannot be null");
		this.authenticationEntryPoint = authenticationEntryPoint;
	}

	/**
	 * Set the {@link AuthenticationFailureHandler} to use. Default implementation invokes
	 * {@link AuthenticationEntryPoint}.
	 * @param authenticationFailureHandler the {@code AuthenticationFailureHandler} to use
	 * @since 5.2
	 */
	public void setAuthenticationFailureHandler(final AuthenticationFailureHandler authenticationFailureHandler) {
		Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
		this.authenticationFailureHandler = authenticationFailureHandler;
	}

	/**
	 * Set the {@link AuthenticationConverter} to use. Defaults to
	 * {@link BearerTokenAuthenticationConverter}.
	 * @param authenticationConverter the {@code AuthenticationConverter} to use
	 * @since 5.5
	 */
	public void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}

}
