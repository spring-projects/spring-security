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

package org.springframework.security.oauth2.server.resource.web;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrors;
import org.springframework.util.StringUtils;

/**
 * The default {@link BearerTokenResolver} implementation based on RFC 6750.
 *
 * @author Vedran Pavic
 * @since 5.1
 * @see <a href="https://tools.ietf.org/html/rfc6750#section-2" target="_blank">RFC 6750
 * Section 2: Authenticated Requests</a>
 */
public final class DefaultBearerTokenResolver implements BearerTokenResolver {

	private static final String ACCESS_TOKEN_PARAMETER_NAME = "access_token";

	private static final Pattern authorizationPattern = Pattern.compile("^Bearer (?<token>[a-zA-Z0-9-._~+/]+=*)$",
			Pattern.CASE_INSENSITIVE);

	private boolean allowFormEncodedBodyParameter = false;

	private boolean allowUriQueryParameter = false;

	private String bearerTokenHeaderName = HttpHeaders.AUTHORIZATION;

	@Override
	public String resolve(final HttpServletRequest request) {
		// @formatter:off
		return resolveToken(
			resolveFromAuthorizationHeader(request),
			resolveAccessTokenFromQueryString(request),
			resolveAccessTokenFromBody(request)
		);
		// @formatter:on
	}

	private static String resolveToken(String... accessTokens) {
		if (accessTokens == null || accessTokens.length == 0) {
			return null;
		}

		String accessToken = null;
		for (String token : accessTokens) {
			if (accessToken == null) {
				accessToken = token;
			}
			else if (token != null) {
				BearerTokenError error = BearerTokenErrors
					.invalidRequest("Found multiple bearer tokens in the request");
				throw new OAuth2AuthenticationException(error);
			}
		}

		if (accessToken != null && accessToken.isBlank()) {
			BearerTokenError error = BearerTokenErrors
				.invalidRequest("The requested token parameter is an empty string");
			throw new OAuth2AuthenticationException(error);
		}

		return accessToken;
	}

	private String resolveFromAuthorizationHeader(HttpServletRequest request) {
		String authorization = request.getHeader(this.bearerTokenHeaderName);
		if (!StringUtils.startsWithIgnoreCase(authorization, "bearer")) {
			return null;
		}

		Matcher matcher = authorizationPattern.matcher(authorization);
		if (!matcher.matches()) {
			BearerTokenError error = BearerTokenErrors.invalidToken("Bearer token is malformed");
			throw new OAuth2AuthenticationException(error);
		}

		return matcher.group("token");
	}

	private String resolveAccessTokenFromQueryString(HttpServletRequest request) {
		if (!this.allowUriQueryParameter || !HttpMethod.GET.name().equals(request.getMethod())) {
			return null;
		}

		return resolveToken(request.getParameterValues(ACCESS_TOKEN_PARAMETER_NAME));
	}

	private String resolveAccessTokenFromBody(HttpServletRequest request) {
		if (!this.allowFormEncodedBodyParameter
				|| !MediaType.APPLICATION_FORM_URLENCODED_VALUE.equals(request.getContentType())
				|| HttpMethod.GET.name().equals(request.getMethod())) {
			return null;
		}

		String queryString = request.getQueryString();
		if (queryString != null && queryString.contains(ACCESS_TOKEN_PARAMETER_NAME)) {
			return null;
		}

		return resolveToken(request.getParameterValues(ACCESS_TOKEN_PARAMETER_NAME));
	}

	/**
	 * Set if transport of access token using form-encoded body parameter is supported.
	 * Defaults to {@code false}.
	 * @param allowFormEncodedBodyParameter if the form-encoded body parameter is
	 * supported
	 */
	public void setAllowFormEncodedBodyParameter(boolean allowFormEncodedBodyParameter) {
		this.allowFormEncodedBodyParameter = allowFormEncodedBodyParameter;
	}

	/**
	 * Set if transport of access token using URI query parameter is supported. Defaults
	 * to {@code false}.
	 *
	 * The spec recommends against using this mechanism for sending bearer tokens, and
	 * even goes as far as stating that it was only included for completeness.
	 * @param allowUriQueryParameter if the URI query parameter is supported
	 */
	public void setAllowUriQueryParameter(boolean allowUriQueryParameter) {
		this.allowUriQueryParameter = allowUriQueryParameter;
	}

	/**
	 * Set this value to configure what header is checked when resolving a Bearer Token.
	 * This value is defaulted to {@link HttpHeaders#AUTHORIZATION}.
	 *
	 * This allows other headers to be used as the Bearer Token source such as
	 * {@link HttpHeaders#PROXY_AUTHORIZATION}
	 * @param bearerTokenHeaderName the header to check when retrieving the Bearer Token.
	 * @since 5.4
	 */
	public void setBearerTokenHeaderName(String bearerTokenHeaderName) {
		this.bearerTokenHeaderName = bearerTokenHeaderName;
	}

}
