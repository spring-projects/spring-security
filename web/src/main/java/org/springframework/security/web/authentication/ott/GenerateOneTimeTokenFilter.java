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

package org.springframework.security.web.authentication.ott;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

/**
 * Filter that process a One-Time Token generation request.
 *
 * @author Marcus da Coregio
 * @since 6.4
 * @see OneTimeTokenService
 */
public final class GenerateOneTimeTokenFilter extends OncePerRequestFilter {

	private final OneTimeTokenService tokenService;

	private final OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler;

	private RequestMatcher requestMatcher = antMatcher(HttpMethod.POST, "/ott/generate");

	public GenerateOneTimeTokenFilter(OneTimeTokenService tokenService,
			OneTimeTokenGenerationSuccessHandler tokenGenerationSuccessHandler) {
		Assert.notNull(tokenService, "tokenService cannot be null");
		Assert.notNull(tokenGenerationSuccessHandler, "tokenGenerationSuccessHandler cannot be null");
		this.tokenService = tokenService;
		this.tokenGenerationSuccessHandler = tokenGenerationSuccessHandler;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (!this.requestMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}
		String username = request.getParameter("username");
		if (!StringUtils.hasText(username)) {
			filterChain.doFilter(request, response);
			return;
		}
		GenerateOneTimeTokenRequest generateRequest = new GenerateOneTimeTokenRequest(username);
		OneTimeToken ott = this.tokenService.generate(generateRequest);
		this.tokenGenerationSuccessHandler.handle(request, response, ott);
	}

	/**
	 * Use the given {@link RequestMatcher} to match the request.
	 * @param requestMatcher
	 */
	public void setRequestMatcher(RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.requestMatcher = requestMatcher;
	}

}
