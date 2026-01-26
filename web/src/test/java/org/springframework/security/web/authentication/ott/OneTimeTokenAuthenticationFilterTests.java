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

package org.springframework.security.web.authentication.ott;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.servlet.MockServletContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Tests for {@link OneTimeTokenAuthenticationFilter}.
 *
 * @author Daniel Garnier-Moiroux
 * @since 6.5
 */
@ExtendWith(MockitoExtension.class)
class OneTimeTokenAuthenticationFilterTests {

	@Mock
	private FilterChain chain;

	@Mock
	private AuthenticationManager authenticationManager;

	private final OneTimeTokenAuthenticationFilter filter = new OneTimeTokenAuthenticationFilter();

	private final HttpServletResponse response = new MockHttpServletResponse();

	@BeforeEach
	void setUp() {
		this.filter.setAuthenticationManager(this.authenticationManager);
	}

	@Test
	@SuppressWarnings("removal")
	void setAuthenticationConverterWhenNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setAuthenticationConverter(null));
	}

	@Test
	@SuppressWarnings("removal")
	void doFilterWhenUrlDoesNotMatchThenContinues() throws ServletException, IOException {
		OneTimeTokenAuthenticationConverter converter = mock(OneTimeTokenAuthenticationConverter.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		this.filter.setAuthenticationConverter(converter);
		this.filter.doFilter(post("/nomatch").buildRequest(new MockServletContext()), response, this.chain);
		verifyNoInteractions(converter, response);
		verify(this.chain).doFilter(any(), any());
	}

	@Test
	@SuppressWarnings("removal")
	void doFilterWhenMethodDoesNotMatchThenContinues() throws ServletException, IOException {
		OneTimeTokenAuthenticationConverter converter = mock(OneTimeTokenAuthenticationConverter.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		this.filter.setAuthenticationConverter(converter);
		this.filter.doFilter(get("/login/ott").buildRequest(new MockServletContext()), response, this.chain);
		verifyNoInteractions(converter, response);
		verify(this.chain).doFilter(any(), any());
	}

	@Test
	@SuppressWarnings("removal")
	void doFilterWhenMissingTokenThenPropagatesRequest() throws ServletException, IOException {
		FilterChain chain = mock(FilterChain.class);
		this.filter.doFilter(post("/login/ott").buildRequest(new MockServletContext()), this.response, chain);
		verify(chain).doFilter(any(), any());
	}

	@Test
	@SuppressWarnings("removal")
	void doFilterWhenInvalidTokenThenUnauthorized() throws ServletException, IOException {
		given(this.authenticationManager.authenticate(any())).willThrow(new BadCredentialsException("invalid token"));
		this.filter.doFilter(
				post("/login/ott").param("token", "some-token-value").buildRequest(new MockServletContext()),
				this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
		verifyNoInteractions(this.chain);
	}

	@Test
	@SuppressWarnings("removal")
	void doFilterWhenValidThenRedirectsToSavedRequest() throws ServletException, IOException {
		given(this.authenticationManager.authenticate(any()))
			.willReturn(OneTimeTokenAuthenticationToken.authenticated("username", AuthorityUtils.NO_AUTHORITIES));
		this.filter.doFilter(
				post("/login/ott").param("token", "some-token-value").buildRequest(new MockServletContext()),
				this.response, this.chain);
		assertThat(this.response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
		assertThat(this.response.getHeader("location")).endsWith("/");
	}

}
