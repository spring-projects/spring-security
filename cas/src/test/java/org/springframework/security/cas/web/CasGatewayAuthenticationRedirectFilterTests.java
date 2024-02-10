/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.cas.web;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.web.savedrequest.RequestCache;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link CasGatewayAuthenticationRedirectFilter}.
 *
 * @author Jerome LELEU
 * @author Marcus da Coregio
 */
public class CasGatewayAuthenticationRedirectFilterTests {

	private static final String CAS_LOGIN_URL = "http://mycasserver/login";

	CasGatewayAuthenticationRedirectFilter filter = new CasGatewayAuthenticationRedirectFilter(CAS_LOGIN_URL,
			serviceProperties());

	@Test
	void doFilterWhenMatchesThenSavesRequestAndSavesAttributeAndSendRedirect() throws IOException, ServletException {
		RequestCache requestCache = mock();
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.filter.setRequestMatcher((req) -> true);
		this.filter.setRequestCache(requestCache);
		this.filter.doFilter(request, response, new MockFilterChain());
		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getHeader("Location"))
			.isEqualTo("http://mycasserver/login?service=http%3A%2F%2Flocalhost%2Flogin%2Fcas&gateway=true");
		verify(requestCache).saveRequest(request, response);
	}

	@Test
	void doFilterWhenNotMatchThenContinueFilter() throws ServletException, IOException {
		this.filter.setRequestMatcher((req) -> false);
		FilterChain chain = mock();
		MockHttpServletResponse response = mock();
		this.filter.doFilter(new MockHttpServletRequest(), response, chain);
		verify(chain).doFilter(any(), any());
		verifyNoInteractions(response);
	}

	@Test
	void doFilterWhenSendRenewTrueThenIgnores() throws ServletException, IOException {
		ServiceProperties serviceProperties = serviceProperties();
		serviceProperties.setSendRenew(true);
		this.filter = new CasGatewayAuthenticationRedirectFilter(CAS_LOGIN_URL, serviceProperties);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.filter.setRequestMatcher((req) -> true);
		this.filter.doFilter(request, response, new MockFilterChain());
		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(response.getHeader("Location"))
			.isEqualTo("http://mycasserver/login?service=http%3A%2F%2Flocalhost%2Flogin%2Fcas&gateway=true");
	}

	private static ServiceProperties serviceProperties() {
		ServiceProperties serviceProperties = new ServiceProperties();
		serviceProperties.setService("http://localhost/login/cas");
		return serviceProperties;
	}

}
