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

package org.springframework.security.web.authentication.logout;

import java.util.LinkedHashMap;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * DelegatingLogoutSuccessHandlerTests Tests
 *
 * @author Shazin Sadakath
 * @author Rob Winch
 */
@ExtendWith(MockitoExtension.class)
public class DelegatingLogoutSuccessHandlerTests {

	@Mock
	RequestMatcher matcher;

	@Mock
	RequestMatcher matcher2;

	@Mock
	LogoutSuccessHandler handler;

	@Mock
	LogoutSuccessHandler handler2;

	@Mock
	LogoutSuccessHandler defaultHandler;

	@Mock
	HttpServletRequest request;

	@Mock
	MockHttpServletResponse response;

	@Mock
	Authentication authentication;

	DelegatingLogoutSuccessHandler delegatingHandler;

	@BeforeEach
	public void setup() {
		LinkedHashMap<RequestMatcher, LogoutSuccessHandler> matcherToHandler = new LinkedHashMap<>();
		matcherToHandler.put(this.matcher, this.handler);
		matcherToHandler.put(this.matcher2, this.handler2);
		this.delegatingHandler = new DelegatingLogoutSuccessHandler(matcherToHandler);
	}

	@Test
	public void onLogoutSuccessFirstMatches() throws Exception {
		this.delegatingHandler.setDefaultLogoutSuccessHandler(this.defaultHandler);
		given(this.matcher.matches(this.request)).willReturn(true);
		this.delegatingHandler.onLogoutSuccess(this.request, this.response, this.authentication);
		verify(this.handler).onLogoutSuccess(this.request, this.response, this.authentication);
		verifyNoMoreInteractions(this.matcher2, this.handler2, this.defaultHandler);
	}

	@Test
	public void onLogoutSuccessSecondMatches() throws Exception {
		this.delegatingHandler.setDefaultLogoutSuccessHandler(this.defaultHandler);
		given(this.matcher2.matches(this.request)).willReturn(true);
		this.delegatingHandler.onLogoutSuccess(this.request, this.response, this.authentication);
		verify(this.handler2).onLogoutSuccess(this.request, this.response, this.authentication);
		verifyNoMoreInteractions(this.handler, this.defaultHandler);
	}

	@Test
	public void onLogoutSuccessDefault() throws Exception {
		this.delegatingHandler.setDefaultLogoutSuccessHandler(this.defaultHandler);
		this.delegatingHandler.onLogoutSuccess(this.request, this.response, this.authentication);
		verify(this.defaultHandler).onLogoutSuccess(this.request, this.response, this.authentication);
		verifyNoMoreInteractions(this.handler, this.handler2);
	}

	@Test
	public void onLogoutSuccessNoMatchDefaultNull() throws Exception {
		this.delegatingHandler.onLogoutSuccess(this.request, this.response, this.authentication);
		verifyNoMoreInteractions(this.handler, this.handler2, this.defaultHandler);
	}

}
