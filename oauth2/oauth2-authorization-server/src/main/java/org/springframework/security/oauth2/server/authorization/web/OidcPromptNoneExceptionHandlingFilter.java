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
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A {@code Filter} that handles OIDC {@code prompt=none} requests by translating
 * authentication and authorization exceptions into OAuth2/OIDC error responses.
 *
 * <p>
 * This filter is placed after {@code ExceptionTranslationFilter} and before
 * {@code AuthorizationFilter} to catch {@code AccessDeniedException} and
 * {@code AuthenticationException} when {@code prompt=none} is specified, and convert them
 * to proper OIDC error responses (e.g., {@code login_required}) instead of redirecting to
 * the login page.
 *
 * <p>
 * The filter does NOT change authorization decisions - it only translates exceptions into
 * protocol-compliant error responses when {@code prompt=none} is present.
 *
 * @author suuuuuuminnnnnn
 * @since 7.0
 * @see OAuth2AuthorizationCodeRequestAuthenticationException
 */
public final class OidcPromptNoneExceptionHandlingFilter extends OncePerRequestFilter {

	private final RequestMatcher authorizationEndpointMatcher;

	private final AuthenticationConverter authenticationConverter;

	private final AuthenticationFailureHandler authenticationFailureHandler;

	public OidcPromptNoneExceptionHandlingFilter(RequestMatcher authorizationEndpointMatcher,
			AuthenticationConverter authenticationConverter,
			AuthenticationFailureHandler authenticationFailureHandler) {

		Assert.notNull(authorizationEndpointMatcher, "authorizationEndpointMatcher cannot be null");
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");

		this.authorizationEndpointMatcher = authorizationEndpointMatcher;
		this.authenticationConverter = authenticationConverter;
		this.authenticationFailureHandler = authenticationFailureHandler;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.authorizationEndpointMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		OAuth2AuthorizationCodeRequestAuthenticationToken authRequest = null;
		try {
			Authentication authentication = this.authenticationConverter.convert(request);
			if (authentication instanceof OAuth2AuthorizationCodeRequestAuthenticationToken) {
				authRequest = (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
			}
		}
		catch (OAuth2AuthorizationCodeRequestAuthenticationException ex) {
			// If converter throws an exception with client/redirect info, use it
			if (ex.getAuthorizationCodeRequestAuthentication() != null) {
				authRequest = ex.getAuthorizationCodeRequestAuthentication();
			}
		}
		catch (Exception ex) {
			// Ignore other conversion errors, let other filters handle them
		}

		try {
			filterChain.doFilter(request, response);

		}
		catch (AccessDeniedException ex) {
			if (authRequest != null && isPromptNone(authRequest)) {
				handlePromptNoneError(request, response, authRequest, "login_required");
				return;
			}
			throw ex;

		}
		catch (AuthenticationException ex) {
			if (authRequest != null && isPromptNone(authRequest)) {
				handlePromptNoneError(request, response, authRequest, "login_required");
				return;
			}
			throw ex;
		}
	}

	private static boolean isPromptNone(OAuth2AuthorizationCodeRequestAuthenticationToken authRequest) {
		if (!authRequest.getScopes().contains(OidcScopes.OPENID)) {
			return false;
		}

		String prompt = (String) authRequest.getAdditionalParameters().get("prompt");
		if (!StringUtils.hasText(prompt)) {
			return false;
		}

		Set<String> promptValues = new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(prompt, " ")));

		return promptValues.contains("none");
	}

	private void handlePromptNoneError(HttpServletRequest request, HttpServletResponse response,
			OAuth2AuthorizationCodeRequestAuthenticationToken authRequest, String errorCode)
			throws IOException, ServletException {

		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: prompt",
				"https://openid.net/specs/openid-connect-core-1_0.html#AuthError");

		OAuth2AuthorizationCodeRequestAuthenticationToken errorAuthRequest = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				authRequest.getAuthorizationUri(), authRequest.getClientId(),
				(Authentication) authRequest.getPrincipal(), authRequest.getRedirectUri(), authRequest.getState(),
				authRequest.getScopes(), authRequest.getAdditionalParameters());

		OAuth2AuthorizationCodeRequestAuthenticationException authException = new OAuth2AuthorizationCodeRequestAuthenticationException(
				error, errorAuthRequest);

		this.authenticationFailureHandler.onAuthenticationFailure(request, response, authException);
	}

}
