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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.security.web.util.matcher.JavascriptOriginRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * RequestMatcherLogoutSuccessHandler Tests
 *
 * @author Shazin Sadakath
 */
@RunWith(MockitoJUnitRunner.class)
public class RequestMatcherLogoutSuccessHandlerTests {

	private RequestMatcherLogoutSuccessHandler customLogoutSuccessHandler = new RequestMatcherLogoutSuccessHandler();

	@Before
	public void init() {
		Map<RequestMatcher, LogoutSuccessHandler> requestMatcherLogoutSuccessHandlerMap = new LinkedHashMap();
		requestMatcherLogoutSuccessHandlerMap.put(new IpAddressMatcher("192.168.1.5"), new SimpleUrlLogoutSuccessHandler());
		requestMatcherLogoutSuccessHandlerMap.put(new MediaTypeRequestMatcher(new HeaderContentNegotiationStrategy(), MediaType.APPLICATION_JSON), new HttpStatusReturningLogoutSuccessHandler(HttpStatus.CREATED));
		customLogoutSuccessHandler.setRequestMatcherLogoutSuccessHandlers(requestMatcherLogoutSuccessHandlerMap);
	}

	@Test
	public void javascriptOriginRequest() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		LogoutSuccessHandler logoutSuccessHandler = new RequestMatcherLogoutSuccessHandler();

		request.addHeader(JavascriptOriginRequestMatcher.HTTP_X_REQUESTED_WITH, "XMLHttpRequest");

		logoutSuccessHandler.onLogoutSuccess(request, response, mock(Authentication.class));

		assertThat(response.getStatus()).isEqualTo(HttpStatus.NO_CONTENT.value());
	}

	@Test
	public void nonJavascriptOriginRequest() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		LogoutSuccessHandler logoutSuccessHandler = new RequestMatcherLogoutSuccessHandler();

		logoutSuccessHandler.onLogoutSuccess(request, response, mock(Authentication.class));

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
	}

	@Test
	public void customRequestMatcherHandlerMap_IPAddress() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRemoteAddr("192.168.1.5");
		MockHttpServletResponse response = new MockHttpServletResponse();

		customLogoutSuccessHandler.onLogoutSuccess(request, response, mock(Authentication.class));

		assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
	}

	@Test
	public void customRequestMatcherHandlerMap_AcceptHeader() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
		MockHttpServletResponse response = new MockHttpServletResponse();

		customLogoutSuccessHandler.onLogoutSuccess(request, response, mock(Authentication.class));

		assertThat(response.getStatus()).isEqualTo(HttpStatus.CREATED.value());
	}

}
