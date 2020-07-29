/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.web.savedrequest;

import java.util.Base64;

import javax.servlet.http.Cookie;

import org.junit.Test;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

public class RequestCacheAwareFilterTests {

	@Test
	public void doFilterWhenHttpSessionRequestCacheConfiguredThenSavedRequestRemovedAfterMatch() throws Exception {
		RequestCacheAwareFilter filter = new RequestCacheAwareFilter();
		HttpSessionRequestCache cache = new HttpSessionRequestCache();

		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/destination");
		MockHttpServletResponse response = new MockHttpServletResponse();
		cache.saveRequest(request, response);
		assertThat(request.getSession().getAttribute(HttpSessionRequestCache.SAVED_REQUEST)).isNotNull();

		filter.doFilter(request, response, new MockFilterChain());
		assertThat(request.getSession().getAttribute(HttpSessionRequestCache.SAVED_REQUEST)).isNull();
	}

	@Test
	public void doFilterWhenCookieRequestCacheConfiguredThenExpiredSavedRequestCookieSetAfterMatch() throws Exception {
		CookieRequestCache cache = new CookieRequestCache();
		RequestCacheAwareFilter filter = new RequestCacheAwareFilter(cache);

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServerName("abc.com");
		request.setRequestURI("/destination");
		request.setScheme("https");
		request.setServerPort(443);
		request.setSecure(true);

		String encodedRedirectUrl = Base64.getEncoder().encodeToString("https://abc.com/destination".getBytes());
		Cookie savedRequest = new Cookie("REDIRECT_URI", encodedRedirectUrl);
		savedRequest.setMaxAge(-1);
		savedRequest.setSecure(request.isSecure());
		savedRequest.setPath("/");
		savedRequest.setHttpOnly(true);
		request.setCookies(savedRequest);

		MockHttpServletResponse response = new MockHttpServletResponse();

		filter.doFilter(request, response, new MockFilterChain());

		Cookie expiredCookie = response.getCookie("REDIRECT_URI");
		assertThat(expiredCookie).isNotNull();
		assertThat(expiredCookie.getValue()).isEmpty();
		assertThat(expiredCookie.getMaxAge()).isZero();
	}

}
