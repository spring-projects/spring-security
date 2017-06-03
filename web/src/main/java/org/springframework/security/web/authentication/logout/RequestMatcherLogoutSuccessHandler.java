/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.web.authentication.logout;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.util.matcher.JavascriptOriginRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Delegates to logout handlers based on matched request matchers
 *
 * @author Shazin Sadakath
 */
public class RequestMatcherLogoutSuccessHandler implements LogoutSuccessHandler {

	private Map<RequestMatcher, LogoutSuccessHandler> requestMatcherLogoutSuccessHandlers = new LinkedHashMap();

	public RequestMatcherLogoutSuccessHandler() {
		requestMatcherLogoutSuccessHandlers.put(new JavascriptOriginRequestMatcher(), new HttpStatusReturningLogoutSuccessHandler(HttpStatus.NO_CONTENT));
		requestMatcherLogoutSuccessHandlers.put(new NegatedRequestMatcher(new JavascriptOriginRequestMatcher()), new SimpleUrlLogoutSuccessHandler());
	}

	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
		for(Map.Entry<RequestMatcher, LogoutSuccessHandler> entry : requestMatcherLogoutSuccessHandlers.entrySet()) {
			if(entry.getKey().matches(request)) {
				entry.getValue().onLogoutSuccess(request, response, authentication);
				break;
			}
		}
	}

	public Map<RequestMatcher, LogoutSuccessHandler> getRequestMatcherLogoutSuccessHandlers() {
		return requestMatcherLogoutSuccessHandlers;
	}

	public void setRequestMatcherLogoutSuccessHandlers(Map<RequestMatcher, LogoutSuccessHandler> requestMatcherLogoutSuccessHandlers) {
		Assert.notNull(requestMatcherLogoutSuccessHandlers, "must not be null");
		this.requestMatcherLogoutSuccessHandlers = requestMatcherLogoutSuccessHandlers;
	}
}
