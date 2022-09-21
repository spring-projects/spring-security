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

package org.springframework.security.web.authentication;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * @author Sergey Bespalov
 * @since 5.2.0
 */
@ExtendWith(MockitoExtension.class)
public class AuthenticationFilterTests {

	@Mock
	private AuthenticationSuccessHandler successHandler;

	@Mock
	private AuthenticationConverter authenticationConverter;

	@Mock
	private AuthenticationManager authenticationManager;

	@Mock
	private AuthenticationFailureHandler failureHandler;

	@Mock
	private AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver;

	@Mock
	private RequestMatcher requestMatcher;

	private void givenResolveWillReturnAuthenticationManager() {
		given(this.authenticationManagerResolver.resolve(any())).willReturn(this.authenticationManager);
	}

	@AfterEach
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void filterWhenDefaultsAndNoAuthenticationThenContinues() throws Exception {
		AuthenticationFilter filter = new AuthenticationFilter(this.authenticationManager,
				this.authenticationConverter);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		verifyNoMoreInteractions(this.authenticationManager);
		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void filterWhenAuthenticationManagerResolverDefaultsAndNoAuthenticationThenContinues() throws Exception {
		AuthenticationFilter filter = new AuthenticationFilter(this.authenticationManagerResolver,
				this.authenticationConverter);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		verifyNoMoreInteractions(this.authenticationManagerResolver);
		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void filterWhenDefaultsAndAuthenticationSuccessThenContinues() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("test", "this", "ROLE");
		given(this.authenticationConverter.convert(any())).willReturn(authentication);
		given(this.authenticationManager.authenticate(any())).willReturn(authentication);
		AuthenticationFilter filter = new AuthenticationFilter(this.authenticationManager,
				this.authenticationConverter);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		verify(this.authenticationManager).authenticate(any(Authentication.class));
		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(request.getAttribute(RequestAttributeSecurityContextRepository.DEFAULT_REQUEST_ATTR_NAME))
				.isNotNull();
	}

	@Test
	public void filterWhenCustomSecurityContextHolderStrategyThenUses() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("test", "this", "ROLE");
		given(this.authenticationConverter.convert(any())).willReturn(authentication);
		given(this.authenticationManager.authenticate(any())).willReturn(authentication);
		AuthenticationFilter filter = new AuthenticationFilter(this.authenticationManager,
				this.authenticationConverter);
		SecurityContextHolderStrategy strategy = mock(SecurityContextHolderStrategy.class);
		given(strategy.createEmptyContext()).willReturn(new SecurityContextImpl());
		filter.setSecurityContextHolderStrategy(strategy);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		verify(this.authenticationManager).authenticate(any(Authentication.class));
		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		verify(strategy).setContext(any());
	}

	@Test
	public void filterWhenAuthenticationManagerResolverDefaultsAndAuthenticationSuccessThenContinues()
			throws Exception {
		givenResolveWillReturnAuthenticationManager();
		Authentication authentication = new TestingAuthenticationToken("test", "this", "ROLE");
		given(this.authenticationConverter.convert(any())).willReturn(authentication);
		given(this.authenticationManager.authenticate(any())).willReturn(authentication);
		AuthenticationFilter filter = new AuthenticationFilter(this.authenticationManagerResolver,
				this.authenticationConverter);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		verify(this.authenticationManager).authenticate(any(Authentication.class));
		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(request.getAttribute(RequestAttributeSecurityContextRepository.DEFAULT_REQUEST_ATTR_NAME))
				.isNotNull();
	}

	@Test
	public void filterWhenDefaultsAndAuthenticationFailThenUnauthorized() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("test", "this", "ROLE");
		given(this.authenticationConverter.convert(any())).willReturn(authentication);
		given(this.authenticationManager.authenticate(any())).willThrow(new BadCredentialsException("failed"));
		AuthenticationFilter filter = new AuthenticationFilter(this.authenticationManager,
				this.authenticationConverter);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		assertThat(response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void filterWhenAuthenticationManagerResolverDefaultsAndAuthenticationFailThenUnauthorized()
			throws Exception {
		givenResolveWillReturnAuthenticationManager();
		Authentication authentication = new TestingAuthenticationToken("test", "this", "ROLE");
		given(this.authenticationConverter.convert(any())).willReturn(authentication);
		given(this.authenticationManager.authenticate(any())).willThrow(new BadCredentialsException("failed"));
		AuthenticationFilter filter = new AuthenticationFilter(this.authenticationManagerResolver,
				this.authenticationConverter);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		assertThat(response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void filterWhenConvertEmptyThenOk() throws Exception {
		given(this.authenticationConverter.convert(any())).willReturn(null);
		AuthenticationFilter filter = new AuthenticationFilter(this.authenticationManagerResolver,
				this.authenticationConverter);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, new MockHttpServletResponse(), chain);
		verifyNoMoreInteractions(this.authenticationManagerResolver);
		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void filterWhenConvertAndAuthenticationSuccessThenSuccess() throws Exception {
		givenResolveWillReturnAuthenticationManager();
		Authentication authentication = new TestingAuthenticationToken("test", "this", "ROLE_USER");
		given(this.authenticationConverter.convert(any())).willReturn(authentication);
		given(this.authenticationManager.authenticate(any())).willReturn(authentication);
		AuthenticationFilter filter = new AuthenticationFilter(this.authenticationManagerResolver,
				this.authenticationConverter);
		filter.setSuccessHandler(this.successHandler);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		verify(this.successHandler).onAuthenticationSuccess(any(), any(), any(), eq(authentication));
		verifyNoMoreInteractions(this.failureHandler);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(request.getAttribute(RequestAttributeSecurityContextRepository.DEFAULT_REQUEST_ATTR_NAME))
				.isNotNull();
	}

	@Test
	public void filterWhenConvertAndAuthenticationEmptyThenServerError() throws Exception {
		givenResolveWillReturnAuthenticationManager();
		Authentication authentication = new TestingAuthenticationToken("test", "this", "ROLE_USER");
		given(this.authenticationConverter.convert(any())).willReturn(authentication);
		given(this.authenticationManager.authenticate(any())).willReturn(null);
		AuthenticationFilter filter = new AuthenticationFilter(this.authenticationManagerResolver,
				this.authenticationConverter);
		filter.setSuccessHandler(this.successHandler);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		assertThatExceptionOfType(ServletException.class).isThrownBy(() -> filter.doFilter(request, response, chain));
		verifyNoMoreInteractions(this.successHandler);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void filterWhenNotMatchAndConvertAndAuthenticationSuccessThenContinues() throws Exception {
		given(this.requestMatcher.matches(any())).willReturn(false);
		AuthenticationFilter filter = new AuthenticationFilter(this.authenticationManagerResolver,
				this.authenticationConverter);
		filter.setRequestMatcher(this.requestMatcher);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		verifyNoMoreInteractions(this.authenticationConverter, this.authenticationManagerResolver, this.successHandler);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	// gh-7446
	@Test
	public void filterWhenSuccessfulAuthenticationThenSessionIdChanges() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("test", "this", "ROLE_USER");
		given(this.authenticationConverter.convert(any())).willReturn(authentication);
		given(this.authenticationManager.authenticate(any())).willReturn(authentication);
		MockHttpSession session = new MockHttpSession();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		request.setSession(session);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = new MockFilterChain();
		String sessionId = session.getId();
		AuthenticationFilter filter = new AuthenticationFilter(this.authenticationManager,
				this.authenticationConverter);
		filter.doFilter(request, response, chain);
		assertThat(session.getId()).isNotEqualTo(sessionId);
	}

	@Test
	public void filterWhenSuccessfulAuthenticationThenNoSessionCreated() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("test", "this", "ROLE_USER");
		given(this.authenticationConverter.convert(any())).willReturn(authentication);
		given(this.authenticationManager.authenticate(any())).willReturn(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = new MockFilterChain();
		AuthenticationFilter filter = new AuthenticationFilter(this.authenticationManager,
				this.authenticationConverter);
		filter.doFilter(request, response, chain);
		assertThat(request.getSession(false)).isNull();
	}

	@Test
	public void filterWhenCustomSecurityContextRepositoryAndSuccessfulAuthenticationRepositoryUsed() throws Exception {
		SecurityContextRepository securityContextRepository = mock(SecurityContextRepository.class);
		ArgumentCaptor<SecurityContext> securityContextArg = ArgumentCaptor.forClass(SecurityContext.class);
		Authentication authentication = new TestingAuthenticationToken("test", "this", "ROLE_USER");
		given(this.authenticationConverter.convert(any())).willReturn(authentication);
		given(this.authenticationManager.authenticate(any())).willReturn(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = new MockFilterChain();
		AuthenticationFilter filter = new AuthenticationFilter(this.authenticationManager,
				this.authenticationConverter);
		filter.setSecurityContextRepository(securityContextRepository);
		filter.doFilter(request, response, chain);
		verify(securityContextRepository).saveContext(securityContextArg.capture(), eq(request), eq(response));
		assertThat(securityContextArg.getValue().getAuthentication()).isEqualTo(authentication);
	}

}
