/*
 * Copyright 2004-present the original author or authors.
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

import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

/**
 * @author Luke Taylor
 * @author Eddú Meléndez
 * @since 3.0
 */
public class HttpSessionRequestCacheTests {

	@Test
	public void originalGetRequestDoesntMatchIncomingPost() {
		HttpSessionRequestCache cache = new HttpSessionRequestCache();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/destination");
		MockHttpServletResponse response = new MockHttpServletResponse();
		cache.saveRequest(request, response);
		assertThat(request.getSession().getAttribute(HttpSessionRequestCache.SAVED_REQUEST)).isNotNull();
		assertThat(cache.getRequest(request, response)).isNotNull();
		MockHttpServletRequest newRequest = new MockHttpServletRequest("POST", "/destination");
		newRequest.setSession(request.getSession());
		assertThat(cache.getMatchingRequest(newRequest, response)).isNull();
	}

	@Test
	public void requestMatcherDefinesCorrectSubsetOfCachedRequests() {
		HttpSessionRequestCache cache = new HttpSessionRequestCache();
		cache.setRequestMatcher((request) -> request.getMethod().equals("GET"));
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/destination");
		MockHttpServletResponse response = new MockHttpServletResponse();
		cache.saveRequest(request, response);
		assertThat(cache.getRequest(request, response)).isNull();
		assertThat(cache.getRequest(new MockHttpServletRequest(), new MockHttpServletResponse())).isNull();
		assertThat(cache.getMatchingRequest(request, response)).isNull();
	}

	// SEC-2246
	@Test
	public void getRequestCustomNoClassCastException() {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/destination");
		MockHttpServletResponse response = new MockHttpServletResponse();
		HttpSessionRequestCache cache = new HttpSessionRequestCache() {
			@Override
			public void saveRequest(HttpServletRequest request, HttpServletResponse response) {
				request.getSession()
					.setAttribute(SAVED_REQUEST, new CustomSavedRequest(new DefaultSavedRequest(request)));
			}
		};
		cache.saveRequest(request, response);
		cache.saveRequest(request, response);
		assertThat(cache.getRequest(request, response)).isInstanceOf(CustomSavedRequest.class);
	}

	@Test
	public void testCustomSessionAttrName() {
		HttpSessionRequestCache cache = new HttpSessionRequestCache();
		cache.setSessionAttrName("CUSTOM_SAVED_REQUEST");
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/destination");
		MockHttpServletResponse response = new MockHttpServletResponse();
		cache.saveRequest(request, response);
		assertThat(request.getSession().getAttribute(HttpSessionRequestCache.SAVED_REQUEST)).isNull();
		assertThat(request.getSession().getAttribute("CUSTOM_SAVED_REQUEST")).isNotNull();
	}

	@Test
	public void getMatchingRequestWhenMatchingRequestParameterNameSetThenSessionNotAccessed() {
		HttpSessionRequestCache cache = new HttpSessionRequestCache();
		cache.setMatchingRequestParameterName("success");
		HttpServletRequest request = spy(new MockHttpServletRequest());
		HttpServletRequest matchingRequest = cache.getMatchingRequest(request, new MockHttpServletResponse());
		assertThat(matchingRequest).isNull();
		verify(request, never()).getSession();
		verify(request, never()).getSession(anyBoolean());
	}

	@Test
	public void getMatchingRequestWhenMatchingRequestParameterNameSetAndParameterExistThenLookedUp() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		HttpSessionRequestCache cache = new HttpSessionRequestCache();
		cache.setMatchingRequestParameterName("success");
		cache.saveRequest(request, new MockHttpServletResponse());
		MockHttpServletRequest requestToMatch = new MockHttpServletRequest();
		requestToMatch.setQueryString("success"); // gh-12665
		requestToMatch.setSession(request.getSession());
		HttpServletRequest matchingRequest = cache.getMatchingRequest(requestToMatch, new MockHttpServletResponse());
		assertThat(matchingRequest).isNotNull();
	}

	// gh-12665
	@Test
	public void getMatchingRequestWhenMatchingRequestParameterNameSetAndParameterExistAndQueryThenLookedUp() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("param=true");
		HttpSessionRequestCache cache = new HttpSessionRequestCache();
		cache.setMatchingRequestParameterName("success");
		cache.saveRequest(request, new MockHttpServletResponse());
		MockHttpServletRequest requestToMatch = new MockHttpServletRequest();
		requestToMatch.setQueryString("param=true&success");
		requestToMatch.setSession(request.getSession());
		HttpServletRequest matchingRequest = cache.getMatchingRequest(requestToMatch, new MockHttpServletResponse());
		assertThat(matchingRequest).isNotNull();
	}

	@Test
	public void getMatchingRequestWhenMatchesThenRemoved() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		HttpSessionRequestCache cache = new HttpSessionRequestCache();
		cache.setMatchingRequestParameterName("success");
		cache.saveRequest(request, new MockHttpServletResponse());
		assertThat(request.getSession().getAttribute(HttpSessionRequestCache.SAVED_REQUEST)).isNotNull();
		MockHttpServletRequest requestToMatch = new MockHttpServletRequest();
		requestToMatch.setQueryString("success");
		requestToMatch.setSession(request.getSession());
		HttpServletRequest matchingRequest = cache.getMatchingRequest(requestToMatch, new MockHttpServletResponse());
		assertThat(matchingRequest).isNotNull();
		assertThat(request.getSession().getAttribute(HttpSessionRequestCache.SAVED_REQUEST)).isNull();
	}

	// gh-13731
	@Test
	public void getMatchingRequestWhenMatchingRequestParameterNameSetThenDoesNotInvokeGetParameterMethods() {
		HttpSessionRequestCache cache = new HttpSessionRequestCache();
		cache.setMatchingRequestParameterName("success");
		MockHttpServletRequest mockRequest = new MockHttpServletRequest();
		mockRequest.setQueryString("success");
		HttpServletRequest request = spy(mockRequest);
		HttpServletRequest matchingRequest = cache.getMatchingRequest(request, new MockHttpServletResponse());
		assertThat(matchingRequest).isNull();
		verify(request, never()).getParameter(anyString());
		verify(request, never()).getParameterValues(anyString());
		verify(request, never()).getParameterNames();
		verify(request, never()).getParameterMap();
	}

	private static final class CustomSavedRequest implements SavedRequest {

		private final SavedRequest delegate;

		private CustomSavedRequest(SavedRequest delegate) {
			this.delegate = delegate;
		}

		@Override
		public String getRedirectUrl() {
			return this.delegate.getRedirectUrl();
		}

		@Override
		public List<Cookie> getCookies() {
			return this.delegate.getCookies();
		}

		@Override
		public String getMethod() {
			return this.delegate.getMethod();
		}

		@Override
		public List<String> getHeaderValues(String name) {
			return this.delegate.getHeaderValues(name);
		}

		@Override
		public Collection<String> getHeaderNames() {
			return this.delegate.getHeaderNames();
		}

		@Override
		public List<Locale> getLocales() {
			return this.delegate.getLocales();
		}

		@Override
		public String[] getParameterValues(String name) {
			return this.delegate.getParameterValues(name);
		}

		@Override
		public Map<String, String[]> getParameterMap() {
			return this.delegate.getParameterMap();
		}

		private static final long serialVersionUID = 2426831999233621470L;

	}

}
