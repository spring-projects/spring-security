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

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * @author Zeeshan Adnan
 */
public class CookieRequestCacheTests {

	private static final String DEFAULT_COOKIE_NAME = "REDIRECT_URI";

	@Test
	public void saveRequestWhenMatchesThenSavedRequestInACookieOnResponse() {
		CookieRequestCache cookieRequestCache = new CookieRequestCache();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServerPort(443);
		request.setSecure(true);
		request.setScheme("https");
		request.setServerName("abc.com");
		request.setRequestURI("/destination");
		request.setQueryString("param1=a&param2=b&param3=1122");
		MockHttpServletResponse response = new MockHttpServletResponse();
		cookieRequestCache.saveRequest(request, response);
		Cookie savedCookie = response.getCookie(DEFAULT_COOKIE_NAME);
		assertThat(savedCookie).isNotNull();
		String redirectUrl = decodeCookie(savedCookie.getValue());
		assertThat(redirectUrl).isEqualTo("https://abc.com/destination?param1=a&param2=b&param3=1122");
		assertThat(savedCookie.getMaxAge()).isEqualTo(-1);
		assertThat(savedCookie.getPath()).isEqualTo("/");
		assertThat(savedCookie.isHttpOnly()).isTrue();
		assertThat(savedCookie.getSecure()).isTrue();
	}

	@Test
	public void setRequestMatcherWhenRequestMatcherIsSetNullThenThrowsIllegalArgumentException() {
		CookieRequestCache cookieRequestCache = new CookieRequestCache();
		assertThatIllegalArgumentException().isThrownBy(() -> cookieRequestCache.setRequestMatcher(null));
	}

	@Test
	public void getMatchingRequestWhenRequestMatcherDefinedThenReturnsCorrectSubsetOfCachedRequests() {
		CookieRequestCache cookieRequestCache = new CookieRequestCache();
		cookieRequestCache.setRequestMatcher((request) -> request.getRequestURI().equals("/expected-destination"));
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/destination");
		MockHttpServletResponse response = new MockHttpServletResponse();
		cookieRequestCache.saveRequest(request, response);
		SavedRequest savedRequest = cookieRequestCache.getRequest(request, response);
		assertThat(savedRequest).isNull();
		HttpServletRequest matchingRequest = cookieRequestCache.getMatchingRequest(request, response);
		assertThat(matchingRequest).isNull();
	}

	@Test
	public void getRequestWhenRequestIsWithoutCookiesThenReturnsNullSavedRequest() {
		CookieRequestCache cookieRequestCache = new CookieRequestCache();
		SavedRequest savedRequest = cookieRequestCache.getRequest(new MockHttpServletRequest(),
				new MockHttpServletResponse());
		assertThat(savedRequest).isNull();
	}

	@Test
	public void getRequestWhenRequestDoesNotContainSavedRequestCookieThenReturnsNull() {
		CookieRequestCache cookieRequestCache = new CookieRequestCache();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setCookies(new Cookie("abc_cookie", "value"));
		SavedRequest savedRequest = cookieRequestCache.getRequest(request, new MockHttpServletResponse());
		assertThat(savedRequest).isNull();
	}

	@Test
	public void getRequestWhenRequestContainsSavedRequestCookieThenReturnsSaveRequest() {
		CookieRequestCache cookieRequestCache = new CookieRequestCache();
		MockHttpServletRequest request = new MockHttpServletRequest();
		String redirectUrl = "https://abc.com/destination?param1=a&param2=b&param3=1122";
		request.setCookies(new Cookie(DEFAULT_COOKIE_NAME, encodeCookie(redirectUrl)));
		SavedRequest savedRequest = cookieRequestCache.getRequest(request, new MockHttpServletResponse());
		assertThat(savedRequest).isNotNull();
		assertThat(savedRequest.getRedirectUrl()).isEqualTo(redirectUrl);
	}

	@Test
	public void matchingRequestWhenRequestDoesNotContainSavedRequestCookieThenReturnsNull() {
		CookieRequestCache cookieRequestCache = new CookieRequestCache();
		MockHttpServletResponse response = new MockHttpServletResponse();
		HttpServletRequest matchingRequest = cookieRequestCache.getMatchingRequest(new MockHttpServletRequest(),
				response);
		assertThat(matchingRequest).isNull();
		assertThat(response.getCookie(DEFAULT_COOKIE_NAME)).isNull();
	}

	@Test
	public void matchingRequestWhenRequestContainsSavedRequestCookieThenSetsAnExpiredCookieInResponse() {
		CookieRequestCache cookieRequestCache = new CookieRequestCache();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServerPort(443);
		request.setSecure(true);
		request.setScheme("https");
		request.setServerName("abc.com");
		request.setRequestURI("/destination");
		request.setQueryString("param1=a&param2=b&param3=1122");
		String redirectUrl = "https://abc.com/destination?param1=a&param2=b&param3=1122";
		request.setCookies(new Cookie(DEFAULT_COOKIE_NAME, encodeCookie(redirectUrl)));
		MockHttpServletResponse response = new MockHttpServletResponse();
		cookieRequestCache.getMatchingRequest(request, response);
		Cookie expiredCookie = response.getCookie(DEFAULT_COOKIE_NAME);
		assertThat(expiredCookie).isNotNull();
		assertThat(expiredCookie.getValue()).isEmpty();
		assertThat(expiredCookie.getMaxAge()).isZero();
	}

	@Test
	public void requestWhenDoesNotMatchSavedRequestThenDoesNotClearCookie() {
		CookieRequestCache cookieRequestCache = new CookieRequestCache();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServerPort(443);
		request.setSecure(true);
		request.setScheme("https");
		request.setServerName("abc.com");
		request.setRequestURI("/destination");
		String redirectUrl = "https://abc.com/api";
		request.setCookies(new Cookie(DEFAULT_COOKIE_NAME, encodeCookie(redirectUrl)));
		MockHttpServletResponse response = new MockHttpServletResponse();
		final HttpServletRequest matchingRequest = cookieRequestCache.getMatchingRequest(request, response);
		assertThat(matchingRequest).isNull();
		Cookie expiredCookie = response.getCookie(DEFAULT_COOKIE_NAME);
		assertThat(expiredCookie).isNull();
	}

	@Test
	public void matchingRequestWhenUrlEncodedQueryParametersThenDoesNotDuplicate() {
		CookieRequestCache cookieRequestCache = new CookieRequestCache();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServerPort(443);
		request.setSecure(true);
		request.setScheme("https");
		request.setServerName("abc.com");
		request.setRequestURI("/destination");
		request.setQueryString("goto=https%3A%2F%2Fstart.spring.io");
		request.setParameter("goto", "https://start.spring.io");
		String redirectUrl = "https://abc.com/destination?goto=https%3A%2F%2Fstart.spring.io";
		request.setCookies(new Cookie(DEFAULT_COOKIE_NAME, encodeCookie(redirectUrl)));
		MockHttpServletResponse response = new MockHttpServletResponse();
		final HttpServletRequest matchingRequest = cookieRequestCache.getMatchingRequest(request, response);
		assertThat(matchingRequest).isNotNull();
		assertThat(matchingRequest.getParameterValues("goto")).containsExactly("https://start.spring.io");
	}

	@Test
	public void removeRequestWhenInvokedThenSetsAnExpiredCookieOnResponse() {
		CookieRequestCache cookieRequestCache = new CookieRequestCache();
		MockHttpServletResponse response = new MockHttpServletResponse();
		cookieRequestCache.removeRequest(new MockHttpServletRequest(), response);
		Cookie expiredCookie = response.getCookie(DEFAULT_COOKIE_NAME);
		assertThat(expiredCookie).isNotNull();
		assertThat(expiredCookie.getValue()).isEmpty();
		assertThat(expiredCookie.getMaxAge()).isZero();
	}

	private static String encodeCookie(String cookieValue) {
		return Base64.getEncoder().encodeToString(cookieValue.getBytes());
	}

	private static String decodeCookie(String encodedCookieValue) {
		return new String(Base64.getDecoder().decode(encodedCookieValue.getBytes()));
	}

}
