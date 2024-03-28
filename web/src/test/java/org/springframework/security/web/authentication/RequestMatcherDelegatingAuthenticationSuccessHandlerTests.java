/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.authentication;

import java.util.LinkedHashMap;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link RequestMatcherDelegatingAuthenticationSuccessHandler}
 *
 * @author Max Batischev
 * @since 6.3
 */
public class RequestMatcherDelegatingAuthenticationSuccessHandlerTests {

	private RequestMatcherDelegatingAuthenticationSuccessHandler delegatingAuthenticationSuccessHandler;

	private LinkedHashMap<RequestMatcher, AuthenticationSuccessHandler> accessHandlers;

	private AuthenticationSuccessHandler authenticationSuccessHandler;

	private HttpServletRequest request;

	@BeforeEach
	public void setup() {
		this.authenticationSuccessHandler = mock(AuthenticationSuccessHandler.class);
		this.accessHandlers = new LinkedHashMap<>();
		this.request = new MockHttpServletRequest();
	}

	@Test
	public void handleWhenNoMatchesThenDefaultHandlerExecuted() throws Exception {
		AuthenticationSuccessHandler handler = mock(AuthenticationSuccessHandler.class);
		Authentication authentication = mock(Authentication.class);
		RequestMatcher matcher = mock(RequestMatcher.class);
		given(matcher.matches(this.request)).willReturn(false);
		this.accessHandlers.put(matcher, handler);
		this.delegatingAuthenticationSuccessHandler = new RequestMatcherDelegatingAuthenticationSuccessHandler(
				this.accessHandlers, this.authenticationSuccessHandler);

		this.delegatingAuthenticationSuccessHandler.onAuthenticationSuccess(this.request, null, authentication);

		verify(this.authenticationSuccessHandler).onAuthenticationSuccess(this.request, null, authentication);
		verify(handler, never()).onAuthenticationSuccess(this.request, null, authentication);
	}

	@Test
	public void handleWhenFirstHandlerMatchesThenFirstHandlerExecuted() throws Exception {
		Authentication authentication = mock(Authentication.class);
		AuthenticationSuccessHandler firstHandler = mock(AuthenticationSuccessHandler.class);
		RequestMatcher firstMatcher = mock(RequestMatcher.class);
		AuthenticationSuccessHandler secondHandler = mock(AuthenticationSuccessHandler.class);
		RequestMatcher secondMatcher = mock(RequestMatcher.class);
		given(firstMatcher.matches(this.request)).willReturn(true);
		this.accessHandlers.put(firstMatcher, firstHandler);
		this.accessHandlers.put(secondMatcher, secondHandler);
		this.delegatingAuthenticationSuccessHandler = new RequestMatcherDelegatingAuthenticationSuccessHandler(
				this.accessHandlers, this.authenticationSuccessHandler);

		this.delegatingAuthenticationSuccessHandler.onAuthenticationSuccess(this.request, null, authentication);

		verify(firstHandler).onAuthenticationSuccess(this.request, null, authentication);
		verify(secondHandler, never()).onAuthenticationSuccess(this.request, null, authentication);
		verify(this.authenticationSuccessHandler, never()).onAuthenticationSuccess(this.request, null, authentication);
		verify(secondMatcher, never()).matches(this.request);
	}

	@Test
	public void handleWhenSecondHandlerMatchesThenSecondHandlerExecuted() throws Exception {
		Authentication authentication = mock(Authentication.class);
		AuthenticationSuccessHandler firstHandler = mock(AuthenticationSuccessHandler.class);
		RequestMatcher firstMatcher = mock(RequestMatcher.class);
		AuthenticationSuccessHandler secondHandler = mock(AuthenticationSuccessHandler.class);
		RequestMatcher secondMatcher = mock(RequestMatcher.class);
		given(firstMatcher.matches(this.request)).willReturn(false);
		given(secondMatcher.matches(this.request)).willReturn(true);
		this.accessHandlers.put(firstMatcher, firstHandler);
		this.accessHandlers.put(secondMatcher, secondHandler);
		this.delegatingAuthenticationSuccessHandler = new RequestMatcherDelegatingAuthenticationSuccessHandler(
				this.accessHandlers, this.authenticationSuccessHandler);

		this.delegatingAuthenticationSuccessHandler.onAuthenticationSuccess(this.request, null, authentication);

		verify(secondHandler).onAuthenticationSuccess(this.request, null, authentication);
		verify(firstHandler, never()).onAuthenticationSuccess(this.request, null, authentication);
		verify(this.authenticationSuccessHandler, never()).onAuthenticationSuccess(this.request, null, authentication);
	}

}
