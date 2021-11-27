/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.web.authentication.logout;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Delegates to logout handlers based on matched request matchers
 *
 * @author Shazin Sadakath
 * @author Rob Winch
 * @since 4.1
 */
public class DelegatingLogoutSuccessHandler implements LogoutSuccessHandler {

	private final LinkedHashMap<RequestMatcher, LogoutSuccessHandler> matcherToHandler;

	private LogoutSuccessHandler defaultLogoutSuccessHandler;

	public DelegatingLogoutSuccessHandler(LinkedHashMap<RequestMatcher, LogoutSuccessHandler> matcherToHandler) {
		Assert.notEmpty(matcherToHandler, "matcherToHandler cannot be null");
		this.matcherToHandler = matcherToHandler;
	}

	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
			throws IOException, ServletException {
		for (Map.Entry<RequestMatcher, LogoutSuccessHandler> entry : this.matcherToHandler.entrySet()) {
			RequestMatcher matcher = entry.getKey();
			if (matcher.matches(request)) {
				LogoutSuccessHandler handler = entry.getValue();
				handler.onLogoutSuccess(request, response, authentication);
				return;
			}
		}
		if (this.defaultLogoutSuccessHandler != null) {
			this.defaultLogoutSuccessHandler.onLogoutSuccess(request, response, authentication);
		}
	}

	/**
	 * Sets the default {@link LogoutSuccessHandler} if no other handlers available
	 * @param defaultLogoutSuccessHandler the defaultLogoutSuccessHandler to set
	 */
	public void setDefaultLogoutSuccessHandler(LogoutSuccessHandler defaultLogoutSuccessHandler) {
		this.defaultLogoutSuccessHandler = defaultLogoutSuccessHandler;
	}

}
