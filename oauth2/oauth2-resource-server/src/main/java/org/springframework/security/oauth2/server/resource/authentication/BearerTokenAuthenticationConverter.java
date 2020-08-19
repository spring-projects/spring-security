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

package org.springframework.security.oauth2.server.resource.authentication;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;

/**
 * Converts from a HttpServletRequest to {@link BearerTokenAuthenticationToken} that can
 * be authenticated. Null authentication possible if there was no Authorization header
 * with Bearer Token.
 *
 * @author Jeongjin Kim
 * @since 5.5
 */
public final class BearerTokenAuthenticationConverter implements AuthenticationConverter {

	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

	private BearerTokenResolver bearerTokenResolver;

	public BearerTokenAuthenticationConverter() {
		this.bearerTokenResolver = new DefaultBearerTokenResolver();
	}

	@Override
	public BearerTokenAuthenticationToken convert(HttpServletRequest request) {
		String token = this.bearerTokenResolver.resolve(request);

		if (token == null) {
			return null;
		}

		BearerTokenAuthenticationToken authenticationRequest = new BearerTokenAuthenticationToken(token);
		authenticationRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
		return authenticationRequest;
	}

	/**
	 * Set the {@link BearerTokenResolver} to use. Defaults to
	 * {@link DefaultBearerTokenResolver}.
	 * @param bearerTokenResolver the {@code BearerTokenResolver} to use
	 */
	public void setBearerTokenResolver(BearerTokenResolver bearerTokenResolver) {
		Assert.notNull(bearerTokenResolver, "bearerTokenResolver cannot be null");
		this.bearerTokenResolver = bearerTokenResolver;
	}

	/**
	 * Set the {@link AuthenticationDetailsSource} to use. Defaults to
	 * {@link WebAuthenticationDetailsSource}.
	 * @param authenticationDetailsSource the {@code AuthenticationDetailsSource} to use
	 */
	public void setAuthenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		Assert.notNull(authenticationDetailsSource, "authenticationDetailsSource cannot be null");
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

}
