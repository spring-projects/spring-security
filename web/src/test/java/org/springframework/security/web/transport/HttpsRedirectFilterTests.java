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

package org.springframework.security.web.transport;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link HttpsRedirectFilter}
 *
 * @author Josh Cummings
 */
@ExtendWith(MockitoExtension.class)
public class HttpsRedirectFilterTests {

	HttpsRedirectFilter filter;

	@Mock
	FilterChain chain;

	@BeforeEach
	public void configureFilter() {
		this.filter = new HttpsRedirectFilter();
	}

	@Test
	public void filterWhenRequestIsInsecureThenRedirects() throws Exception {
		HttpServletRequest request = get("http://localhost");
		HttpServletResponse response = ok();
		this.filter.doFilter(request, response, this.chain);
		assertThat(statusCode(response)).isEqualTo(302);
		assertThat(redirectedUrl(response)).isEqualTo("https://localhost");
	}

	@Test
	public void filterWhenExchangeIsSecureThenNoRedirect() throws Exception {
		HttpServletRequest request = get("https://localhost");
		HttpServletResponse response = ok();
		this.filter.doFilter(request, response, this.chain);
		assertThat(statusCode(response)).isEqualTo(200);
	}

	@Test
	public void filterWhenExchangeMismatchesThenNoRedirect() throws Exception {
		RequestMatcher matcher = mock(RequestMatcher.class);
		this.filter.setRequestMatcher(matcher);
		HttpServletRequest request = get("http://localhost:8080");
		HttpServletResponse response = ok();
		this.filter.doFilter(request, response, this.chain);
		assertThat(statusCode(response)).isEqualTo(200);
	}

	@Test
	public void filterWhenExchangeMatchesAndRequestIsInsecureThenRedirects() throws Exception {
		RequestMatcher matcher = mock(RequestMatcher.class);
		given(matcher.matches(any())).willReturn(true);
		this.filter.setRequestMatcher(matcher);
		HttpServletRequest request = get("http://localhost:8080");
		HttpServletResponse response = ok();
		this.filter.doFilter(request, response, this.chain);
		assertThat(statusCode(response)).isEqualTo(302);
		assertThat(redirectedUrl(response)).isEqualTo("https://localhost:8443");
		verify(matcher).matches(any(HttpServletRequest.class));
	}

	@Test
	public void filterWhenRequestIsInsecureThenPortMapperRemapsPort() throws Exception {
		PortMapper portMapper = mock(PortMapper.class);
		given(portMapper.lookupHttpsPort(314)).willReturn(159);
		this.filter.setPortMapper(portMapper);
		HttpServletRequest request = get("http://localhost:314");
		HttpServletResponse response = ok();
		this.filter.doFilter(request, response, this.chain);
		assertThat(statusCode(response)).isEqualTo(302);
		assertThat(redirectedUrl(response)).isEqualTo("https://localhost:159");
		verify(portMapper).lookupHttpsPort(314);
	}

	@Test
	public void filterWhenRequestIsInsecureAndNoPortMappingThenThrowsIllegalState() {
		HttpServletRequest request = get("http://localhost:1234");
		HttpServletResponse response = ok();
		assertThatIllegalStateException().isThrownBy(() -> this.filter.doFilter(request, response, this.chain));
	}

	@Test
	public void filterWhenInsecureRequestHasAPathThenRedirects() throws Exception {
		HttpServletRequest request = get("http://localhost:8080/path/page.html?query=string");
		HttpServletResponse response = ok();
		this.filter.doFilter(request, response, this.chain);
		assertThat(statusCode(response)).isEqualTo(302);
		assertThat(redirectedUrl(response)).isEqualTo("https://localhost:8443/path/page.html?query=string");
	}

	@Test
	public void setRequiresTransportSecurityMatcherWhenSetWithNullValueThenThrowsIllegalArgument() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setRequestMatcher(null));
	}

	@Test
	public void setPortMapperWhenSetWithNullValueThenThrowsIllegalArgument() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setPortMapper(null));
	}

	private String redirectedUrl(HttpServletResponse response) {
		return response.getHeader(HttpHeaders.LOCATION);
	}

	private int statusCode(HttpServletResponse response) {
		return response.getStatus();
	}

	private HttpServletRequest get(String uri) {
		UriComponents components = UriComponentsBuilder.fromUriString(uri).build();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", components.getPath());
		request.setQueryString(components.getQuery());
		if (components.getScheme() != null) {
			request.setScheme(components.getScheme());
		}
		int port = components.getPort();
		if (port != -1) {
			request.setServerPort(port);
		}
		return request;
	}

	private HttpServletResponse ok() {
		MockHttpServletResponse response = new MockHttpServletResponse();
		response.setStatus(200);
		return response;
	}

}
