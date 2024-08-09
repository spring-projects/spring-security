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

package org.springframework.security.web.authentication.passwordless.ott;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.passwordless.ott.OneTimeToken;
import org.springframework.security.authentication.passwordless.ott.OneTimeTokenAuthenticationRequest;
import org.springframework.security.authentication.passwordless.ott.OneTimeTokenService;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

public class OneTimeTokenAuthenticationRequestFilter extends OncePerRequestFilter {

	private final OneTimeTokenService oneTimeTokenService;

	private OneTimeTokenAuthenticationRequestSuccessHandler successHandler = new RedirectOneTimeTokenAuthenticationRequestSuccessHandler(
			"/login/ott");

	private RequestMatcher requestMatcher = new AntPathRequestMatcher("/ott/authenticate", "POST");

	private OneTimeTokenAuthenticationRequestResolver authenticationRequestResolver = new RequestParameterOneTimeTokenAuthenticationRequestResolver();

	public OneTimeTokenAuthenticationRequestFilter(OneTimeTokenService oneTimeTokenService) {
		Assert.notNull(oneTimeTokenService, "oneTimeTokenService cannot be null");
		this.oneTimeTokenService = oneTimeTokenService;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (!this.requestMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}
		OneTimeTokenAuthenticationRequest authenticationRequest = this.authenticationRequestResolver.resolve(request);
		if (authenticationRequest == null) {
			filterChain.doFilter(request, response);
			return;
		}
		OneTimeToken ott = this.oneTimeTokenService.generate(authenticationRequest);
		this.successHandler.handle(request, response, filterChain, ott);
	}

	public void setRequestMatcher(RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.requestMatcher = requestMatcher;
	}

	public void setAuthenticationRequestResolver(
			OneTimeTokenAuthenticationRequestResolver authenticationRequestResolver) {
		Assert.notNull(authenticationRequestResolver, "authenticationRequestResolver cannot be null");
		this.authenticationRequestResolver = authenticationRequestResolver;
	}

	public void setSuccessHandler(OneTimeTokenAuthenticationRequestSuccessHandler successHandler) {
		Assert.notNull(successHandler, "successHandler cannot be null");
		this.successHandler = successHandler;
	}

}
