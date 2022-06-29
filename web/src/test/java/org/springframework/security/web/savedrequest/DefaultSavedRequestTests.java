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

package org.springframework.security.web.savedrequest;

import java.net.URL;

import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.MockPortResolver;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
public class DefaultSavedRequestTests {

	// SEC-308, SEC-315
	@Test
	public void headersAreCaseInsensitive() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("USER-aGenT", "Mozilla");
		DefaultSavedRequest saved = new DefaultSavedRequest(request, new MockPortResolver(8080, 8443));
		assertThat(saved.getHeaderValues("user-agent").get(0)).isEqualTo("Mozilla");
	}

	// SEC-1412
	@Test
	public void discardsIfNoneMatchHeader() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("If-None-Match", "somehashvalue");
		DefaultSavedRequest saved = new DefaultSavedRequest(request, new MockPortResolver(8080, 8443));
		assertThat(saved.getHeaderValues("if-none-match").isEmpty()).isTrue();
	}

	// SEC-3082
	@Test
	public void parametersAreCaseSensitive() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addParameter("AnotHerTest", "Hi dad");
		request.addParameter("thisisatest", "Hi mom");
		DefaultSavedRequest saved = new DefaultSavedRequest(request, new MockPortResolver(8080, 8443));
		assertThat(saved.getParameterValues("thisisatest")[0]).isEqualTo("Hi mom");
		assertThat(saved.getParameterValues("anothertest")).isNull();
	}

	@Test
	public void getRedirectUrlWhenNoQueryAndDefaultMatchingRequestParameterNameThenNoQuery() throws Exception {
		DefaultSavedRequest savedRequest = new DefaultSavedRequest(new MockHttpServletRequest(),
				new MockPortResolver(8080, 8443));
		assertThat(savedRequest.getParameterMap()).doesNotContainKey("success");
		assertThat(new URL(savedRequest.getRedirectUrl())).hasNoQuery();
	}

	@Test
	public void getRedirectUrlWhenQueryAndDefaultMatchingRequestParameterNameNullThenNoQuery() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("foo=bar");
		DefaultSavedRequest savedRequest = new DefaultSavedRequest(request, new MockPortResolver(8080, 8443), null);
		assertThat(savedRequest.getParameterMap()).doesNotContainKey("success");
		assertThat(new URL(savedRequest.getRedirectUrl())).hasQuery("foo=bar");
	}

	@Test
	public void getRedirectUrlWhenNoQueryAndNullMatchingRequestParameterNameThenNoQuery() throws Exception {
		DefaultSavedRequest savedRequest = new DefaultSavedRequest(new MockHttpServletRequest(),
				new MockPortResolver(8080, 8443), null);
		assertThat(savedRequest.getParameterMap()).doesNotContainKey("success");
		assertThat(new URL(savedRequest.getRedirectUrl())).hasNoQuery();
	}

	@Test
	public void getRedirectUrlWhenNoQueryAndMatchingRequestParameterNameThenQuery() throws Exception {
		DefaultSavedRequest savedRequest = new DefaultSavedRequest(new MockHttpServletRequest(),
				new MockPortResolver(8080, 8443), "success");
		assertThat(savedRequest.getParameterMap()).doesNotContainKey("success");
		assertThat(new URL(savedRequest.getRedirectUrl())).hasQuery("success");
	}

	@Test
	public void getRedirectUrlWhenQueryEmptyAndMatchingRequestParameterNameThenQuery() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("");
		DefaultSavedRequest savedRequest = new DefaultSavedRequest(request, new MockPortResolver(8080, 8443),
				"success");
		assertThat(savedRequest.getParameterMap()).doesNotContainKey("success");
		assertThat(new URL(savedRequest.getRedirectUrl())).hasQuery("success");
	}

	@Test
	public void getRedirectUrlWhenQueryEndsAmpersandAndMatchingRequestParameterNameThenQuery() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("foo=bar&");
		DefaultSavedRequest savedRequest = new DefaultSavedRequest(request, new MockPortResolver(8080, 8443),
				"success");
		assertThat(savedRequest.getParameterMap()).doesNotContainKey("success");
		assertThat(new URL(savedRequest.getRedirectUrl())).hasQuery("foo=bar&success");
	}

	@Test
	public void getRedirectUrlWhenQueryDoesNotEndAmpersandAndMatchingRequestParameterNameThenQuery() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("foo=bar");
		DefaultSavedRequest savedRequest = new DefaultSavedRequest(request, new MockPortResolver(8080, 8443),
				"success");
		assertThat(savedRequest.getParameterMap()).doesNotContainKey("success");
		assertThat(new URL(savedRequest.getRedirectUrl())).hasQuery("foo=bar&success");
	}

}
