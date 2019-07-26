/*
 * Copyright 2002-2018 the original author or authors.
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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.StringUtils;

/**
 * An {@link AuthenticationEntryPoint} implementation used to commence authentication of protected resource requests
 * using {@link BearerTokenAuthenticationFilter}.
 * <p>
 * Uses information provided by {@link BearerTokenError} to set HTTP response status code and populate
 * {@code WWW-Authenticate} HTTP header.
 *
 * @author Vedran Pavic
 * @since 5.1
 * @see BearerTokenError
 * @see <a href="https://tools.ietf.org/html/rfc6750#section-3" target="_blank">RFC 6750 Section 3: The WWW-Authenticate
 * Response Header Field</a>
 */
public final class BearerTokenAuthenticationEntryPoint implements AuthenticationEntryPoint {

	private String realmName;

	/**
	 * Collect error details from the provided parameters and format according to
	 * RFC 6750, specifically {@code error}, {@code error_description}, {@code error_uri}, and {@code scope}.
	 *
	 * @param request that resulted in an <code>AuthenticationException</code>
	 * @param response so that the user agent can begin authentication
	 * @param authException that caused the invocation
	 */
	@Override
	public void commence(
			HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException)
			throws IOException, ServletException {

		HttpStatus status = HttpStatus.UNAUTHORIZED;

		Map<String, String> parameters = new LinkedHashMap<>();

		if (this.realmName != null) {
			parameters.put("realm", this.realmName);
		}

		if (authException instanceof OAuth2AuthenticationException) {
			OAuth2Error error = ((OAuth2AuthenticationException) authException).getError();

			parameters.put("error", error.getErrorCode());

			if (StringUtils.hasText(error.getDescription())) {
				parameters.put("error_description", error.getDescription());
			}

			if (StringUtils.hasText(error.getUri())) {
				parameters.put("error_uri", error.getUri());
			}

			if (error instanceof BearerTokenError) {
				BearerTokenError bearerTokenError = (BearerTokenError) error;

				if (StringUtils.hasText(bearerTokenError.getScope())) {
					parameters.put("scope", bearerTokenError.getScope());
				}

				status = ((BearerTokenError) error).getHttpStatus();
			}
		}

		String wwwAuthenticate = computeWWWAuthenticateHeaderValue(parameters);

		response.addHeader(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticate);
		response.setStatus(status.value());
	}

	/**
	 * Set the default realm name to use in the bearer token error response
	 *
	 * @param realmName
	 */
	public final void setRealmName(String realmName) {
		this.realmName = realmName;
	}

	private static String computeWWWAuthenticateHeaderValue(Map<String, String> parameters) {
		String wwwAuthenticate = "Bearer";
		if (!parameters.isEmpty()) {
			wwwAuthenticate += parameters.entrySet().stream()
					.map(attribute -> attribute.getKey() + "=\"" + attribute.getValue() + "\"")
					.collect(Collectors.joining(", ", " ", ""));
		}

		return wwwAuthenticate;
	}
}
