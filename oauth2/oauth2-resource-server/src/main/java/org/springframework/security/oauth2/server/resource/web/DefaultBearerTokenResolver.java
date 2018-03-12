/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrorCodes;
import org.springframework.util.StringUtils;

/**
 * The default {@link BearerTokenResolver} implementation based on RFC 6750.
 *
 * @author Vedran Pavic
 * @since 5.1
 * @see <a href="https://tools.ietf.org/html/rfc6750#section-2" target="_blank">RFC 6750 Section 2: Authenticated Requests</a>
 */
public final class DefaultBearerTokenResolver implements BearerTokenResolver {

	private static final Pattern authorizationPattern = Pattern.compile("^Bearer (?<token>[^\\s]+)*$");

	private boolean useFormEncodedBodyParameter = false;

	private boolean useUriQueryParameter = false;

	@Override
	public String resolve(HttpServletRequest request) {
		String authorizationHeaderToken = resolveFromAuthorizationHeader(request);
		String parameterToken = request.getParameter("access_token");
		if (authorizationHeaderToken != null) {
			if (parameterToken != null) {
				BearerTokenError error = new BearerTokenError(BearerTokenErrorCodes.INVALID_REQUEST);
				throw new BearerTokenAuthenticationException(error, error.toString());
			}
			return authorizationHeaderToken;
		}
		else if (parameterToken != null && isParameterTokenSupportedForRequest(request)) {
			return parameterToken;
		}
		return null;
	}

	/**
	 * Set if transport of access token using form-encoded body parameter is supported. Defaults to {@code false}.
	 * @param useFormEncodedBodyParameter if the form-encoded body parameter is supported
	 */
	public void setUseFormEncodedBodyParameter(boolean useFormEncodedBodyParameter) {
		this.useFormEncodedBodyParameter = useFormEncodedBodyParameter;
	}

	/**
	 * Set if transport of access token using URI query parameter is supported. Defaults to {@code false}.
	 * @param useUriQueryParameter if the URI query parameter is supported
	 */
	public void setUseUriQueryParameter(boolean useUriQueryParameter) {
		this.useUriQueryParameter = useUriQueryParameter;
	}

	private static String resolveFromAuthorizationHeader(HttpServletRequest request) {
		String authorization = request.getHeader("Authorization");
		if (StringUtils.hasText(authorization)) {
			Matcher matcher = authorizationPattern.matcher(authorization);
			if (matcher.matches()) {
				return matcher.group("token");
			}
		}
		return null;
	}

	private boolean isParameterTokenSupportedForRequest(HttpServletRequest request) {
		return ((this.useFormEncodedBodyParameter && "POST".equals(request.getMethod()))
				|| (this.useUriQueryParameter && "GET".equals(request.getMethod())));
	}

}
