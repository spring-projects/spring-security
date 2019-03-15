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
package org.springframework.security.oauth2.server.resource.web;

import java.io.IOException;
import javax.servlet.ServletException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrorCodes;
import org.springframework.security.web.AuthenticationEntryPoint;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

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
	AuthenticationManager authenticationManager;

	@Mock
	BearerTokenResolver bearerTokenResolver;

	MockHttpServletRequest request;

	MockHttpServletResponse response;

	MockFilterChain filterChain;

	@InjectMocks
	BearerTokenAuthenticationFilter filter;

	@Before
	public void httpMocks() {
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		this.filterChain = new MockFilterChain();
	}

	@Before
	public void setterMocks() {
		this.filter.setAuthenticationEntryPoint(this.authenticationEntryPoint);
		this.filter.setBearerTokenResolver(this.bearerTokenResolver);
	}

	@Test
	public void doFilterWhenBearerTokenPresentThenAuthenticates() throws ServletException, IOException {
		when(this.bearerTokenResolver.resolve(this.request)).thenReturn("token");

		this.filter.doFilter(this.request, this.response, this.filterChain);

		ArgumentCaptor<BearerTokenAuthenticationToken> captor =
				ArgumentCaptor.forClass(BearerTokenAuthenticationToken.class);

		verify(this.authenticationManager).authenticate(captor.capture());

		assertThat(captor.getValue().getPrincipal()).isEqualTo("token");
	}

	@Test
	public void doFilterWhenNoBearerTokenPresentThenDoesNotAuthenticate()
			throws ServletException, IOException {

		when(this.bearerTokenResolver.resolve(this.request)).thenReturn(null);

		dontAuthenticate();
	}

	@Test
	public void doFilterWhenMalformedBearerTokenThenPropagatesError() throws ServletException, IOException {
		BearerTokenError error = new BearerTokenError(
				BearerTokenErrorCodes.INVALID_REQUEST,
				HttpStatus.BAD_REQUEST,
				"description",
				"uri");

		OAuth2AuthenticationException exception = new OAuth2AuthenticationException(error);

		when(this.bearerTokenResolver.resolve(this.request)).thenThrow(exception);

		dontAuthenticate();

		verify(this.authenticationEntryPoint).commence(this.request, this.response, exception);
	}

	@Test
	public void doFilterWhenAuthenticationFailsThenPropagatesError() throws ServletException, IOException {
		BearerTokenError error = new BearerTokenError(
				BearerTokenErrorCodes.INVALID_TOKEN,
				HttpStatus.UNAUTHORIZED,
				"description",
				"uri"
		);

		OAuth2AuthenticationException exception = new OAuth2AuthenticationException(error);

		when(this.bearerTokenResolver.resolve(this.request)).thenReturn("token");
		when(this.authenticationManager.authenticate(any(BearerTokenAuthenticationToken.class)))
				.thenThrow(exception);

		this.filter.doFilter(this.request, this.response, this.filterChain);

		verify(this.authenticationEntryPoint).commence(this.request, this.response, exception);
	}

	@Test
	public void setAuthenticationEntryPointWhenNullThenThrowsException() {
		assertThatCode(() -> this.filter.setAuthenticationEntryPoint(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("authenticationEntryPoint cannot be null");
	}

	@Test
	public void setBearerTokenResolverWhenNullThenThrowsException() {
		assertThatCode(() -> this.filter.setBearerTokenResolver(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("bearerTokenResolver cannot be null");
	}

	@Test
	public void constructorWhenNullAuthenticationManagerThenThrowsException() {
		assertThatCode(() -> new BearerTokenAuthenticationFilter(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("authenticationManager cannot be null");
	}

	private void dontAuthenticate()
		throws ServletException, IOException {

		this.filter.doFilter(this.request, this.response, this.filterChain);

		verifyNoMoreInteractions(this.authenticationManager);
	}
}
