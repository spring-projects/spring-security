/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.web.access;

import java.util.LinkedHashMap;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * @author Josh Cummings
 */
public class RequestMatcherDelegatingAccessDeniedHandlerTests {

	private RequestMatcherDelegatingAccessDeniedHandler delegator;

	private LinkedHashMap<RequestMatcher, AccessDeniedHandler> deniedHandlers;

	private AccessDeniedHandler accessDeniedHandler;

	private HttpServletRequest request;

	@BeforeEach
	public void setup() {
		this.accessDeniedHandler = mock(AccessDeniedHandler.class);
		this.deniedHandlers = new LinkedHashMap<>();
		this.request = new MockHttpServletRequest();
	}

	@Test
	public void handleWhenNothingMatchesThenOnlyDefaultHandlerInvoked() throws Exception {
		AccessDeniedHandler handler = mock(AccessDeniedHandler.class);
		RequestMatcher matcher = mock(RequestMatcher.class);
		given(matcher.matches(this.request)).willReturn(false);
		this.deniedHandlers.put(matcher, handler);
		this.delegator = new RequestMatcherDelegatingAccessDeniedHandler(this.deniedHandlers, this.accessDeniedHandler);
		this.delegator.handle(this.request, null, null);
		verify(this.accessDeniedHandler).handle(this.request, null, null);
		verify(handler, never()).handle(this.request, null, null);
	}

	@Test
	public void handleWhenFirstMatchesThenOnlyFirstInvoked() throws Exception {
		AccessDeniedHandler firstHandler = mock(AccessDeniedHandler.class);
		RequestMatcher firstMatcher = mock(RequestMatcher.class);
		AccessDeniedHandler secondHandler = mock(AccessDeniedHandler.class);
		RequestMatcher secondMatcher = mock(RequestMatcher.class);
		given(firstMatcher.matches(this.request)).willReturn(true);
		this.deniedHandlers.put(firstMatcher, firstHandler);
		this.deniedHandlers.put(secondMatcher, secondHandler);
		this.delegator = new RequestMatcherDelegatingAccessDeniedHandler(this.deniedHandlers, this.accessDeniedHandler);
		this.delegator.handle(this.request, null, null);
		verify(firstHandler).handle(this.request, null, null);
		verify(secondHandler, never()).handle(this.request, null, null);
		verify(this.accessDeniedHandler, never()).handle(this.request, null, null);
		verify(secondMatcher, never()).matches(this.request);
	}

	@Test
	public void handleWhenSecondMatchesThenOnlySecondInvoked() throws Exception {
		AccessDeniedHandler firstHandler = mock(AccessDeniedHandler.class);
		RequestMatcher firstMatcher = mock(RequestMatcher.class);
		AccessDeniedHandler secondHandler = mock(AccessDeniedHandler.class);
		RequestMatcher secondMatcher = mock(RequestMatcher.class);
		given(firstMatcher.matches(this.request)).willReturn(false);
		given(secondMatcher.matches(this.request)).willReturn(true);
		this.deniedHandlers.put(firstMatcher, firstHandler);
		this.deniedHandlers.put(secondMatcher, secondHandler);
		this.delegator = new RequestMatcherDelegatingAccessDeniedHandler(this.deniedHandlers, this.accessDeniedHandler);
		this.delegator.handle(this.request, null, null);
		verify(secondHandler).handle(this.request, null, null);
		verify(firstHandler, never()).handle(this.request, null, null);
		verify(this.accessDeniedHandler, never()).handle(this.request, null, null);
	}

}
