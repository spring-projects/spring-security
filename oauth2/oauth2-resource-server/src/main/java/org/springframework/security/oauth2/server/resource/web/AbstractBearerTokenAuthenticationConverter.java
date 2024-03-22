/*
 * Copyright 2002-2024 the original author or authors.
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

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrors;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * Base class for bearer token converter implementations.
 *
 * @author Max Batischev
 * @author Rob Winch
 * @since 6.3
 */
public abstract class AbstractBearerTokenAuthenticationConverter<R> {

	private static final Pattern authorizationPattern = Pattern.compile("^Bearer (?<token>[a-zA-Z0-9-._~+/]+=*)$",
			Pattern.CASE_INSENSITIVE);

	private boolean allowUriQueryParameter = false;

	protected String bearerTokenHeaderName = HttpHeaders.AUTHORIZATION;

	protected String token(R request) {
		String authorizationHeaderToken = resolveAuthorizationHeaderToken(request);
		String parameterToken = resolveAccessTokenFromRequest(request);

		if (authorizationHeaderToken != null) {
			if (parameterToken != null) {
				BearerTokenError error = BearerTokenErrors
					.invalidRequest("Found multiple bearer tokens in the request");
				throw new OAuth2AuthenticationException(error);
			}
			return authorizationHeaderToken;
		}
		if (parameterToken != null && isParameterTokenSupportedForRequest(request)) {
			return parameterToken;
		}
		return null;
	}

	protected BearerTokenAuthenticationToken convertBearerToken(String token) {
		if (token.isEmpty()) {
			BearerTokenError error = invalidTokenError();
			throw new OAuth2AuthenticationException(error);
		}
		return new BearerTokenAuthenticationToken(token);
	}

	protected abstract String resolveAuthorizationHeaderToken(R request);

	private String resolveAccessTokenFromRequest(R request) {
		List<String> parameterTokens = resolveParameterTokens(request);
		if (CollectionUtils.isEmpty(parameterTokens)) {
			return null;
		}
		if (parameterTokens.size() == 1) {
			return parameterTokens.get(0);
		}

		BearerTokenError error = BearerTokenErrors.invalidRequest("Found multiple bearer tokens in the request");
		throw new OAuth2AuthenticationException(error);

	}

	protected abstract List<String> resolveParameterTokens(R request);

	/**
	 * Set if transport of access token using URI query parameter is supported. Defaults
	 * to {@code false}.
	 * <p>
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
	 * <p>
	 * This allows other headers to be used as the Bearer Token source such as
	 * {@link HttpHeaders#PROXY_AUTHORIZATION}
	 * @param bearerTokenHeaderName the header to check when retrieving the Bearer Token.
	 * @since 5.4
	 */
	public void setBearerTokenHeaderName(String bearerTokenHeaderName) {
		this.bearerTokenHeaderName = bearerTokenHeaderName;
	}

	protected String resolveFromAuthorizationHeader(String authorization) {
		if (!StringUtils.startsWithIgnoreCase(authorization, "bearer")) {
			return null;
		}
		Matcher matcher = authorizationPattern.matcher(authorization);
		if (!matcher.matches()) {
			BearerTokenError error = invalidTokenError();
			throw new OAuth2AuthenticationException(error);
		}
		return matcher.group("token");
	}

	protected BearerTokenError invalidTokenError() {
		return BearerTokenErrors.invalidToken("Bearer token is malformed");
	}

	private boolean isParameterTokenSupportedForRequest(R request) {
		return this.allowUriQueryParameter && HttpMethod.GET.equals(getHttpMethod(request));
	}

	protected abstract HttpMethod getHttpMethod(R request);

}
