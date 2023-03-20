/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.oauth2.server.resource.web.authentication;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrorCodes;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests {@link BearerTokenAuthenticationFilterTests}
 *
 * @author Josh Cummings
 */
@ExtendWith(MockitoExtension.class)
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

	@Mock
	AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;

	MockHttpServletRequest request;

	MockHttpServletResponse response;

	MockFilterChain filterChain;

	@BeforeEach
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
		assertThat(this.request.getAttribute(RequestAttributeSecurityContextRepository.DEFAULT_REQUEST_ATTR_NAME))
				.isNotNull();
	}

	@Test
	public void doFilterWhenSecurityContextRepositoryThenSaves() throws ServletException, IOException {
		SecurityContextRepository securityContextRepository = mock(SecurityContextRepository.class);
		String token = "token";
		given(this.bearerTokenResolver.resolve(this.request)).willReturn(token);
		TestingAuthenticationToken expectedAuthentication = new TestingAuthenticationToken("test", "password");
		given(this.authenticationManager.authenticate(any())).willReturn(expectedAuthentication);
		BearerTokenAuthenticationFilter filter = addMocks(
				new BearerTokenAuthenticationFilter(this.authenticationManager));
		filter.setSecurityContextRepository(securityContextRepository);
		filter.doFilter(this.request, this.response, this.filterChain);
		ArgumentCaptor<BearerTokenAuthenticationToken> captor = ArgumentCaptor
				.forClass(BearerTokenAuthenticationToken.class);
		verify(this.authenticationManager).authenticate(captor.capture());
		assertThat(captor.getValue().getPrincipal()).isEqualTo(token);
		ArgumentCaptor<SecurityContext> contextArg = ArgumentCaptor.forClass(SecurityContext.class);
		verify(securityContextRepository).saveContext(contextArg.capture(), eq(this.request), eq(this.response));
		assertThat(contextArg.getValue().getAuthentication().getName()).isEqualTo(expectedAuthentication.getName());
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
		assertThat(this.request.getAttribute(RequestAttributeSecurityContextRepository.DEFAULT_REQUEST_ATTR_NAME))
				.isNotNull();
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
	public void doFilterWhenAuthenticationServiceExceptionThenRethrows() {
		AuthenticationServiceException exception = new AuthenticationServiceException("message");
		given(this.bearerTokenResolver.resolve(this.request)).willReturn("token");
		given(this.authenticationManager.authenticate(any())).willThrow(exception);
		BearerTokenAuthenticationFilter filter = addMocks(
				new BearerTokenAuthenticationFilter(this.authenticationManager));
		assertThatExceptionOfType(AuthenticationServiceException.class)
				.isThrownBy(() -> filter.doFilter(this.request, this.response, this.filterChain));
	}

	@Test
	public void doFilterWhenCustomEntryPointAndAuthenticationErrorThenUses() throws ServletException, IOException {
		AuthenticationException exception = new InvalidBearerTokenException("message");
		given(this.bearerTokenResolver.resolve(this.request)).willReturn("token");
		given(this.authenticationManager.authenticate(any())).willThrow(exception);
		BearerTokenAuthenticationFilter filter = addMocks(
				new BearerTokenAuthenticationFilter(this.authenticationManager));
		AuthenticationEntryPoint entrypoint = mock(AuthenticationEntryPoint.class);
		filter.setAuthenticationEntryPoint(entrypoint);
		filter.doFilter(this.request, this.response, this.filterChain);
		verify(entrypoint).commence(any(), any(), any(InvalidBearerTokenException.class));
	}

	@Test
	public void doFilterWhenCustomAuthenticationDetailsSourceThenUses() throws ServletException, IOException {
		given(this.bearerTokenResolver.resolve(this.request)).willReturn("token");
		BearerTokenAuthenticationFilter filter = addMocks(
				new BearerTokenAuthenticationFilter(this.authenticationManager));
		filter.doFilter(this.request, this.response, this.filterChain);
		verify(this.authenticationDetailsSource).buildDetails(this.request);
	}

	@Test
	public void doFilterWhenCustomSecurityContextHolderStrategyThenUses() throws ServletException, IOException {
		given(this.bearerTokenResolver.resolve(this.request)).willReturn("token");
		BearerTokenAuthenticationFilter filter = addMocks(
				new BearerTokenAuthenticationFilter(this.authenticationManager));
		SecurityContextHolderStrategy strategy = mock(SecurityContextHolderStrategy.class);
		given(strategy.createEmptyContext()).willReturn(new SecurityContextImpl());
		filter.setSecurityContextHolderStrategy(strategy);
		filter.doFilter(this.request, this.response, this.filterChain);
		verify(strategy).setContext(any());
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
	public void setAuthenticationConverterWhenNullThenThrowsException() {
		// @formatter:off
		BearerTokenAuthenticationFilter filter = new BearerTokenAuthenticationFilter(this.authenticationManager);
		assertThatIllegalArgumentException()
				.isThrownBy(() -> filter.setAuthenticationDetailsSource(null))
				.withMessageContaining("authenticationDetailsSource cannot be null");
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
		filter.setAuthenticationDetailsSource(this.authenticationDetailsSource);
		return filter;
	}

	private void dontAuthenticate() throws ServletException, IOException {
		BearerTokenAuthenticationFilter filter = addMocks(
				new BearerTokenAuthenticationFilter(this.authenticationManager));
		filter.doFilter(this.request, this.response, this.filterChain);
		verifyNoMoreInteractions(this.authenticationManager);
	}

}
