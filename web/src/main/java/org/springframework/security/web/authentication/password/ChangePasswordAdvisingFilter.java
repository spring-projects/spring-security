/*
 * Copyright 2025 the original author or authors.
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

package org.springframework.security.web.authentication.password;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.password.ChangePasswordAdvice;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import static org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher.pathPattern;

public class ChangePasswordAdvisingFilter extends OncePerRequestFilter {

	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	private final String changePasswordUrl;

	private RequestCache requestCache = new NullRequestCache();

	private ChangePasswordAdviceRepository changePasswordAdviceRepository = new HttpSessionChangePasswordAdviceRepository();

	private RequestMatcher requestMatcher;

	public ChangePasswordAdvisingFilter(String changePasswordUrl) {
		this.changePasswordUrl = changePasswordUrl;
		this.requestMatcher = new NegatedRequestMatcher(pathPattern(changePasswordUrl));
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		if (!this.requestMatcher.matches(request)) {
			chain.doFilter(request, response);
			return;
		}
		ChangePasswordAdvice advice = this.changePasswordAdviceRepository.loadPasswordAdvice(request);
		if (advice.getAction() != ChangePasswordAdvice.Action.MUST_CHANGE) {
			chain.doFilter(request, response);
			return;
		}
		this.requestCache.saveRequest(request, response);
		this.redirectStrategy.sendRedirect(request, response, this.changePasswordUrl);
	}

	public void setChangePasswordAdviceRepository(ChangePasswordAdviceRepository changePasswordAdviceRepository) {
		this.changePasswordAdviceRepository = changePasswordAdviceRepository;
	}

	public void setRequestCache(RequestCache requestCache) {
		this.requestCache = requestCache;
	}

	public void setRequestMatcher(RequestMatcher requestMatcher) {
		this.requestMatcher = requestMatcher;
	}

}
