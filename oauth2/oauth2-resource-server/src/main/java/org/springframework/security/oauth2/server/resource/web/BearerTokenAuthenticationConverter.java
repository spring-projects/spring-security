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

import java.util.Collections;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Implementation of {@link AuthenticationConverter}, which converts bearer token to
 * {@link BearerTokenAuthenticationToken}
 *
 * @author Max Batischev
 * @since 6.3
 */
public final class BearerTokenAuthenticationConverter
		extends AbstractBearerTokenAuthenticationConverter<HttpServletRequest> implements AuthenticationConverter {

	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

	@Override
	public Authentication convert(HttpServletRequest request) {
		String token = token(request);
		if (StringUtils.hasText(token)) {
			BearerTokenAuthenticationToken bearerToken = convertBearerToken(token);
			bearerToken.setDetails(this.authenticationDetailsSource.buildDetails(request));
			return bearerToken;
		}
		return null;
	}

	@Override
	protected String resolveAuthorizationHeaderToken(HttpServletRequest request) {
		return resolveFromAuthorizationHeader(request.getHeader(this.bearerTokenHeaderName));
	}

	@Override
	protected List<String> resolveParameterTokens(HttpServletRequest request) {
		String[] queryParameters = request.getParameterValues("access_token");
		if (queryParameters != null) {
			return List.of(queryParameters);
		}
		return Collections.emptyList();
	}

	@Override
	protected HttpMethod getHttpMethod(HttpServletRequest request) {
		return HttpMethod.valueOf(request.getMethod());
	}

	public void setAuthenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		Assert.notNull(authenticationDetailsSource, "authenticationDetailsSource cannot be null");
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	public AuthenticationDetailsSource<HttpServletRequest, ?> getAuthenticationDetailsSource() {
		return this.authenticationDetailsSource;
	}

}
