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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Tests {@link TriggerCasGatewayFilter}.
 *
 * @author Jerome LELEU
 */
public class TriggerCasGatewayFilterTests {

	private static final String CAS_LOGIN_URL = "http://mycasserver/login";

	@AfterEach
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void testGettersSetters() {
		ServiceProperties sp = new ServiceProperties();
		TriggerCasGatewayFilter filter = new TriggerCasGatewayFilter(CAS_LOGIN_URL, sp);
		assertThat(filter.getLoginUrl()).isEqualTo(CAS_LOGIN_URL);
		assertThat(filter.getServiceProperties()).isEqualTo(sp);
		assertThat(filter.getRequestMatcher().getClass()).isEqualTo(CasCookieGatewayRequestMatcher.class);
		assertThat(filter.getRequestCache().getClass()).isEqualTo(HttpSessionRequestCache.class);
		RequestMatcher requestMatcher = mock(RequestMatcher.class);
		filter.setRequestMatcher(requestMatcher);
		assertThat(filter.getRequestMatcher()).isEqualTo(requestMatcher);
		assertThatExceptionOfType(RuntimeException.class).isThrownBy(() -> filter.setRequestMatcher(null));
		RequestCache requestCache = mock(RequestCache.class);
		filter.setRequestCache(requestCache);
		assertThat(filter.getRequestCache()).isEqualTo(requestCache);
		assertThatExceptionOfType(RuntimeException.class).isThrownBy(() -> filter.setRequestCache(null));
	}

	@Test
	public void testOperation() throws IOException, ServletException {
		ServiceProperties sp = new ServiceProperties();
		sp.setService("http://myservice");
		TriggerCasGatewayFilter filter = new TriggerCasGatewayFilter(CAS_LOGIN_URL, sp);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);

		filter.doFilter(request, response, chain);
		assertThat(filter.getRequestCache().getRequest(request, response)).isNotNull();
		assertThat(request.getSession(false).getAttribute(TriggerCasGatewayFilter.TRIGGER_CAS_GATEWAY_AUTHENTICATION))
			.isEqualTo(true);
		assertThat(response.getStatus()).isEqualTo(302);
		assertThat(response.getRedirectedUrl())
			.isEqualTo(CAS_LOGIN_URL + "?service=http%3A%2F%2Fmyservice&gateway=true");
		verify(chain, never()).doFilter(request, response);

		filter.doFilter(request, response, chain);
		verify(chain, times(1)).doFilter(request, response);
	}

}
