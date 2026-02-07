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

package org.springframework.security.oauth2.server.authorization.web.authentication;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

/**
 * An {@link AuthenticationFailureHandler} for OAuth2 Authorization Code Request failures.
 * Handles {@link OAuth2AuthorizationCodeRequestAuthenticationException} by redirecting to
 * the client's redirect URI with the appropriate OAuth2 error parameters.
 *
 * @author suuuuuuminnnnnn
 * @since 7.0
 * @see OAuth2AuthorizationCodeRequestAuthenticationException
 */
public final class OAuth2AuthorizationCodeRequestAuthenticationFailureHandler implements AuthenticationFailureHandler {

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {

		OAuth2AuthorizationCodeRequestAuthenticationException authException = (OAuth2AuthorizationCodeRequestAuthenticationException) exception;

		OAuth2Error error = authException.getError();
		OAuth2AuthorizationCodeRequestAuthenticationToken authRequest = authException
			.getAuthorizationCodeRequestAuthentication();

		if (authRequest == null || !StringUtils.hasText(authRequest.getRedirectUri())) {
			response.sendError(HttpStatus.BAD_REQUEST.value(), error.toString());
			return;
		}

		UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(authRequest.getRedirectUri())
			.queryParam(OAuth2ParameterNames.ERROR, error.getErrorCode());

		if (StringUtils.hasText(error.getDescription())) {
			uriBuilder.queryParam(OAuth2ParameterNames.ERROR_DESCRIPTION,
					UriUtils.encode(error.getDescription(), StandardCharsets.UTF_8));
		}

		if (StringUtils.hasText(error.getUri())) {
			uriBuilder.queryParam(OAuth2ParameterNames.ERROR_URI,
					UriUtils.encode(error.getUri(), StandardCharsets.UTF_8));
		}

		if (StringUtils.hasText(authRequest.getState())) {
			uriBuilder.queryParam(OAuth2ParameterNames.STATE,
					UriUtils.encode(authRequest.getState(), StandardCharsets.UTF_8));
		}

		String redirectUri = uriBuilder.build(true).toUriString();
		response.sendRedirect(redirectUri);
	}

}
