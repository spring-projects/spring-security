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

package org.springframework.security.web.debug;

import java.util.Collections;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.debug.DebugFilter.DebugRequestWrapper;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.security.web.servlet.TestMockHttpServletRequests.get;

/**
 * @author Rob Winch
 *
 */
@ExtendWith(MockitoExtension.class)
public class DebugFilterTests {

	@Captor
	private ArgumentCaptor<HttpServletRequest> requestCaptor;

	@Captor
	private ArgumentCaptor<String> logCaptor;

	@Mock
	private HttpServletRequest request;

	@Mock
	private HttpServletResponse response;

	@Mock
	private FilterChain filterChain;

	@Mock
	private FilterChainProxy fcp;

	@Mock
	private Logger logger;

	private String requestAttr;

	private DebugFilter filter;

	@BeforeEach
	public void setUp() {
		this.filter = new DebugFilter(this.fcp);
		ReflectionTestUtils.setField(this.filter, "logger", this.logger);
		this.requestAttr = DebugFilter.ALREADY_FILTERED_ATTR_NAME;
	}

	private void setupMocks() {
		given(this.request.getHeaderNames()).willReturn(Collections.enumeration(Collections.<String>emptyList()));
		given(this.request.getServletPath()).willReturn("/login");
	}

	@Test
	public void doFilterProcessesRequests() throws Exception {
		setupMocks();
		this.filter.doFilter(this.request, this.response, this.filterChain);
		verify(this.logger).info(anyString());
		verify(this.request).setAttribute(this.requestAttr, Boolean.TRUE);
		verify(this.fcp).doFilter(this.requestCaptor.capture(), eq(this.response), eq(this.filterChain));
		assertThat(this.requestCaptor.getValue().getClass()).isEqualTo(DebugRequestWrapper.class);
		verify(this.request).removeAttribute(this.requestAttr);
	}

	// SEC-1901
	@Test
	public void doFilterProcessesForwardedRequests() throws Exception {
		setupMocks();
		given(this.request.getAttribute(this.requestAttr)).willReturn(Boolean.TRUE);
		HttpServletRequest request = new DebugRequestWrapper(this.request);
		this.filter.doFilter(request, this.response, this.filterChain);
		verify(this.logger).info(anyString());
		verify(this.fcp).doFilter(request, this.response, this.filterChain);
		verify(this.request, never()).removeAttribute(this.requestAttr);
	}

	@Test
	public void doFilterDoesNotWrapWithDebugRequestWrapperAgain() throws Exception {
		setupMocks();
		given(this.request.getAttribute(this.requestAttr)).willReturn(Boolean.TRUE);
		HttpServletRequest fireWalledRequest = new HttpServletRequestWrapper(new DebugRequestWrapper(this.request));
		this.filter.doFilter(fireWalledRequest, this.response, this.filterChain);
		verify(this.fcp).doFilter(fireWalledRequest, this.response, this.filterChain);
	}

	@Test
	public void doFilterLogsProperly() throws Exception {
		MockHttpServletRequest request = get().requestUri(null, "/path", "/").build();
		request.addHeader("A", "A Value");
		request.addHeader("A", "Another Value");
		request.addHeader("B", "B Value");
		this.filter.doFilter(request, this.response, this.filterChain);
		verify(this.logger).info(this.logCaptor.capture());
		assertThat(this.logCaptor.getValue()).isEqualTo("Request received for GET '/path/':\n" + "\n" + request + "\n"
				+ "\n" + "servletPath:/path\n" + "pathInfo:/\n" + "headers: \n" + "A: A Value, Another Value\n"
				+ "B: B Value\n" + "\n" + "\n" + "Security filter chain: no match");
	}

}
