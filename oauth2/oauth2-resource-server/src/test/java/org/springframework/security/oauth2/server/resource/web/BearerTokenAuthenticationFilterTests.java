/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.oauth2.server.resource.web;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrorCodes;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests {@link BearerTokenAuthenticationFilterTests}
 *
 * @author Josh Cummings
 */
@RunWith(MockitoJUnitRunner.class)
public class BearerTokenAuthenticationFilterTests {

	@Mock
	AuthenticationEntryPoint authenticationEntryPoint;

	@Mock
	AuthenticationFailureHandler authenticationFailureHandler;

	@Mock
	AuthenticationManager authenticationManager;

	@Mock
	AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver;

	@Mock
	BearerTokenResolver bearerTokenResolver;

	MockHttpServletRequest request;

	MockHttpServletResponse response;

	MockFilterChain filterChain;

	@Before
	public void httpMocks() {
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		this.filterChain = new MockFilterChain();
	}

	@Test
	public void doFilterWhenBearerTokenPresentThenAuthenticates() throws ServletException, IOException {
		given(this.bearerTokenResolver.resolve(this.request)).willReturn("token");
		BearerTokenAuthenticationFilter filter = addMocks(
				new BearerTokenAuthenticationFilter(this.authenticationManager));
		filter.doFilter(this.request, this.response, this.filterChain);
		ArgumentCaptor<BearerTokenAuthenticationToken> captor = ArgumentCaptor
				.forClass(BearerTokenAuthenticationToken.class);
		verify(this.authenticationManager).authenticate(captor.capture());
		assertThat(captor.getValue().getPrincipal()).isEqualTo("token");
	}

	@Test
	public void doFilterWhenUsingAuthenticationManagerResolverThenAuthenticates() throws Exception {
		BearerTokenAuthenticationFilter filter = addMocks(
				new BearerTokenAuthenticationFilter(this.authenticationManagerResolver));
		given(this.bearerTokenResolver.resolve(this.request)).willReturn("token");
		given(this.authenticationManagerResolver.resolve(any())).willReturn(this.authenticationManager);
		filter.doFilter(this.request, this.response, this.filterChain);
		ArgumentCaptor<BearerTokenAuthenticationToken> captor = ArgumentCaptor
				.forClass(BearerTokenAuthenticationToken.class);
		verify(this.authenticationManager).authenticate(captor.capture());
		assertThat(captor.getValue().getPrincipal()).isEqualTo("token");
	}

	@Test
	public void doFilterWhenNoBearerTokenPresentThenDoesNotAuthenticate() throws ServletException, IOException {
		given(this.bearerTokenResolver.resolve(this.request)).willReturn(null);
		dontAuthenticate();
	}

	@Test
	public void doFilterWhenMalformedBearerTokenThenPropagatesError() throws ServletException, IOException {
		BearerTokenError error = new BearerTokenError(BearerTokenErrorCodes.INVALID_REQUEST, HttpStatus.BAD_REQUEST,
				"description", "uri");
		OAuth2AuthenticationException exception = new OAuth2AuthenticationException(error);
		given(this.bearerTokenResolver.resolve(this.request)).willThrow(exception);
		dontAuthenticate();
		verify(this.authenticationEntryPoint).commence(this.request, this.response, exception);
	}

	@Test
	public void doFilterWhenAuthenticationFailsWithDefaultHandlerThenPropagatesError()
			throws ServletException, IOException {
		BearerTokenError error = new BearerTokenError(BearerTokenErrorCodes.INVALID_TOKEN, HttpStatus.UNAUTHORIZED,
				"description", "uri");
		OAuth2AuthenticationException exception = new OAuth2AuthenticationException(error);
		given(this.bearerTokenResolver.resolve(this.request)).willReturn("token");
		given(this.authenticationManager.authenticate(any(BearerTokenAuthenticationToken.class))).willThrow(exception);
		BearerTokenAuthenticationFilter filter = addMocks(
				new BearerTokenAuthenticationFilter(this.authenticationManager));
		filter.doFilter(this.request, this.response, this.filterChain);
		verify(this.authenticationEntryPoint).commence(this.request, this.response, exception);
	}

	@Test
	public void doFilterWhenAuthenticationFailsWithCustomHandlerThenPropagatesError()
			throws ServletException, IOException {
		BearerTokenError error = new BearerTokenError(BearerTokenErrorCodes.INVALID_TOKEN, HttpStatus.UNAUTHORIZED,
				"description", "uri");
		OAuth2AuthenticationException exception = new OAuth2AuthenticationException(error);
		given(this.bearerTokenResolver.resolve(this.request)).willReturn("token");
		given(this.authenticationManager.authenticate(any(BearerTokenAuthenticationToken.class))).willThrow(exception);
		BearerTokenAuthenticationFilter filter = addMocks(
				new BearerTokenAuthenticationFilter(this.authenticationManager));
		filter.setAuthenticationFailureHandler(this.authenticationFailureHandler);
		filter.doFilter(this.request, this.response, this.filterChain);
		verify(this.authenticationFailureHandler).onAuthenticationFailure(this.request, this.response, exception);
	}

	@Test
	public void setAuthenticationEntryPointWhenNullThenThrowsException() {
		BearerTokenAuthenticationFilter filter = new BearerTokenAuthenticationFilter(this.authenticationManager);
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> filter.setAuthenticationEntryPoint(null))
				.withMessageContaining("authenticationEntryPoint cannot be null");
		// @formatter:on
	}

	@Test
	public void setBearerTokenResolverWhenNullThenThrowsException() {
		BearerTokenAuthenticationFilter filter = new BearerTokenAuthenticationFilter(this.authenticationManager);
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> filter.setBearerTokenResolver(null))
				.withMessageContaining("bearerTokenResolver cannot be null");
		// @formatter:on
	}

	@Test
	public void constructorWhenNullAuthenticationManagerThenThrowsException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new BearerTokenAuthenticationFilter((AuthenticationManager) null))
				.withMessageContaining("authenticationManager cannot be null");
		// @formatter:on
	}

	@Test
	public void constructorWhenNullAuthenticationManagerResolverThenThrowsException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new BearerTokenAuthenticationFilter((AuthenticationManagerResolver<HttpServletRequest>) null))
				.withMessageContaining("authenticationManagerResolver cannot be null");
		// @formatter:on
	}

	private BearerTokenAuthenticationFilter addMocks(BearerTokenAuthenticationFilter filter) {
		filter.setAuthenticationEntryPoint(this.authenticationEntryPoint);
		filter.setBearerTokenResolver(this.bearerTokenResolver);
		return filter;
	}

	private void dontAuthenticate() throws ServletException, IOException {
		BearerTokenAuthenticationFilter filter = addMocks(
				new BearerTokenAuthenticationFilter(this.authenticationManager));
		filter.doFilter(this.request, this.response, this.filterChain);
		verifyNoMoreInteractions(this.authenticationManager);
	}

}
