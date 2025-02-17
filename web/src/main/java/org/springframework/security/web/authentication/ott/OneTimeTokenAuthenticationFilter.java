/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.web.authentication.ott;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;

/**
 * Filter that processes a one-time token for log in.
 * <p>
 * By default, it uses {@link OneTimeTokenAuthenticationConverter} to extract the token
 * from the request.
 *
 * @author Daniel Garnier-Moiroux
 * @since 6.5
 */
public final class OneTimeTokenAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	public static final String DEFAULT_LOGIN_PROCESSING_URL = "/login/ott";

	private AuthenticationConverter authenticationConverter = new OneTimeTokenAuthenticationConverter();

	public OneTimeTokenAuthenticationFilter() {
		super(new AntPathRequestMatcher(DEFAULT_LOGIN_PROCESSING_URL, "POST"));
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		Authentication authentication = this.authenticationConverter.convert(request);
		if (authentication == null) {
			throw new BadCredentialsException("Unable to authenticate with the one-time token");
		}
		return getAuthenticationManager().authenticate(authentication);
	}

	/**
	 * Use this {@link AuthenticationConverter} when converting incoming requests to an
	 * {@link Authentication}. By default, the {@link OneTimeTokenAuthenticationConverter}
	 * is used.
	 * @param authenticationConverter the {@link AuthenticationConverter} to use
	 */
	public void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}

}
