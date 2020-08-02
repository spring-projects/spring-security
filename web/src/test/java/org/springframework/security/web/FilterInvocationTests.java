/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.web;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.FilterInvocation.DummyRequest;
import org.springframework.security.web.util.UrlUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Tests {@link FilterInvocation}.
 *
 * @author Ben Alex
 * @author colin sampaleanu
 */
public class FilterInvocationTests {

	@Test
	public void testGettersAndStringMethods() {
		MockHttpServletRequest request = new MockHttpServletRequest(null, null);
		request.setServletPath("/HelloWorld");
		request.setPathInfo("/some/more/segments.html");
		request.setServerName("localhost");
		request.setScheme("http");
		request.setServerPort(80);
		request.setContextPath("/mycontext");
		request.setRequestURI("/mycontext/HelloWorld/some/more/segments.html");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		FilterInvocation fi = new FilterInvocation(request, response, chain);
		assertThat(fi.getRequest()).isEqualTo(request);
		assertThat(fi.getHttpRequest()).isEqualTo(request);
		assertThat(fi.getResponse()).isEqualTo(response);
		assertThat(fi.getHttpResponse()).isEqualTo(response);
		assertThat(fi.getChain()).isEqualTo(chain);
		assertThat(fi.getRequestUrl()).isEqualTo("/HelloWorld/some/more/segments.html");
		assertThat(fi.toString()).isEqualTo("FilterInvocation: URL: /HelloWorld/some/more/segments.html");
		assertThat(fi.getFullRequestUrl()).isEqualTo("http://localhost/mycontext/HelloWorld/some/more/segments.html");
	}

	@Test(expected = IllegalArgumentException.class)
	public void testRejectsNullFilterChain() {
		MockHttpServletRequest request = new MockHttpServletRequest(null, null);
		MockHttpServletResponse response = new MockHttpServletResponse();
		new FilterInvocation(request, response, null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testRejectsNullServletRequest() {
		MockHttpServletResponse response = new MockHttpServletResponse();
		new FilterInvocation(null, response, mock(FilterChain.class));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testRejectsNullServletResponse() {
		MockHttpServletRequest request = new MockHttpServletRequest(null, null);
		new FilterInvocation(request, null, mock(FilterChain.class));
	}

	@Test
	public void testStringMethodsWithAQueryString() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setQueryString("foo=bar");
		request.setServletPath("/HelloWorld");
		request.setServerName("localhost");
		request.setScheme("http");
		request.setServerPort(80);
		request.setContextPath("/mycontext");
		request.setRequestURI("/mycontext/HelloWorld");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterInvocation fi = new FilterInvocation(request, response, mock(FilterChain.class));
		assertThat(fi.getRequestUrl()).isEqualTo("/HelloWorld?foo=bar");
		assertThat(fi.toString()).isEqualTo("FilterInvocation: URL: /HelloWorld?foo=bar");
		assertThat(fi.getFullRequestUrl()).isEqualTo("http://localhost/mycontext/HelloWorld?foo=bar");
	}

	@Test
	public void testStringMethodsWithoutAnyQueryString() {
		MockHttpServletRequest request = new MockHttpServletRequest(null, null);
		request.setServletPath("/HelloWorld");
		request.setServerName("localhost");
		request.setScheme("http");
		request.setServerPort(80);
		request.setContextPath("/mycontext");
		request.setRequestURI("/mycontext/HelloWorld");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterInvocation fi = new FilterInvocation(request, response, mock(FilterChain.class));
		assertThat(fi.getRequestUrl()).isEqualTo("/HelloWorld");
		assertThat(fi.toString()).isEqualTo("FilterInvocation: URL: /HelloWorld");
		assertThat(fi.getFullRequestUrl()).isEqualTo("http://localhost/mycontext/HelloWorld");
	}

	@Test(expected = UnsupportedOperationException.class)
	public void dummyChainRejectsInvocation() throws Exception {
		FilterInvocation.DUMMY_CHAIN.doFilter(mock(HttpServletRequest.class), mock(HttpServletResponse.class));
	}

	@Test
	public void dummyRequestIsSupportedByUrlUtils() {
		DummyRequest request = new DummyRequest();
		request.setContextPath("");
		request.setRequestURI("/something");
		UrlUtils.buildRequestUrl(request);
	}

}
