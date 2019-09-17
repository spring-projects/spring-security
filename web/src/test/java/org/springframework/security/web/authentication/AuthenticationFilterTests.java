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
package org.springframework.security.web.authentication;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

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
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

/**
 * @author Sergey Bespalov
 * @since 5.2.0
 */
@RunWith(MockitoJUnitRunner.class)
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

	@Before
	public void setup() {
		when(this.authenticationManagerResolver.resolve(any())).thenReturn(this.authenticationManager);
	}

	@After
	public void clearContext() throws Exception {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void filterWhenDefaultsAndNoAuthenticationThenContinues() throws Exception {
		AuthenticationFilter filter = new AuthenticationFilter(this.authenticationManager, this.authenticationConverter);

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);

		verifyZeroInteractions(this.authenticationManager);
		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void filterWhenAuthenticationManagerResolverDefaultsAndNoAuthenticationThenContinues() throws Exception {
		AuthenticationFilter filter = new AuthenticationFilter(this.authenticationManagerResolver, this.authenticationConverter);

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);

		verifyZeroInteractions(this.authenticationManagerResolver);
		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void filterWhenDefaultsAndAuthenticationSuccessThenContinues() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("test", "this", "ROLE");
		when(this.authenticationConverter.convert(any())).thenReturn(authentication);
		when(this.authenticationManager.authenticate(any())).thenReturn(authentication);
		AuthenticationFilter filter = new AuthenticationFilter(this.authenticationManager, this.authenticationConverter);

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);

		verify(this.authenticationManager).authenticate(any(Authentication.class));
		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
	}

	@Test
	public void filterWhenAuthenticationManagerResolverDefaultsAndAuthenticationSuccessThenContinues()
			throws Exception {
		Authentication authentication = new TestingAuthenticationToken("test", "this", "ROLE");
		when(this.authenticationConverter.convert(any())).thenReturn(authentication);
		when(this.authenticationManager.authenticate(any())).thenReturn(authentication);

		AuthenticationFilter filter = new AuthenticationFilter(this.authenticationManagerResolver, this.authenticationConverter);

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);

		verify(this.authenticationManager).authenticate(any(Authentication.class));
		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
	}

	@Test
	public void filterWhenDefaultsAndAuthenticationFailThenUnauthorized() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("test", "this", "ROLE");
		when(this.authenticationConverter.convert(any())).thenReturn(authentication);
		when(this.authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("failed"));

		AuthenticationFilter filter = new AuthenticationFilter(this.authenticationManager, this.authenticationConverter);

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
		Authentication authentication = new TestingAuthenticationToken("test", "this", "ROLE");
		when(this.authenticationConverter.convert(any())).thenReturn(authentication);
		when(this.authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("failed"));

		AuthenticationFilter filter = new AuthenticationFilter(this.authenticationManagerResolver, this.authenticationConverter);

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void filterWhenConvertEmptyThenOk() throws Exception {
		when(this.authenticationConverter.convert(any())).thenReturn(null);
		AuthenticationFilter filter = new AuthenticationFilter(this.authenticationManagerResolver, this.authenticationConverter);

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, new MockHttpServletResponse(), chain);

		verifyZeroInteractions(this.authenticationManagerResolver);
		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void filterWhenConvertAndAuthenticationSuccessThenSuccess() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("test", "this", "ROLE_USER");
		when(this.authenticationConverter.convert(any())).thenReturn(authentication);
		when(this.authenticationManager.authenticate(any())).thenReturn(authentication);

		AuthenticationFilter filter = new AuthenticationFilter(this.authenticationManagerResolver, this.authenticationConverter);
		filter.setSuccessHandler(successHandler);

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);

		verify(this.successHandler).onAuthenticationSuccess(any(), any(), any(), eq(authentication));
		verifyZeroInteractions(this.failureHandler);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
	}

	@Test(expected = ServletException.class)
	public void filterWhenConvertAndAuthenticationEmptyThenServerError() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("test", "this", "ROLE_USER");
		when(this.authenticationConverter.convert(any())).thenReturn(authentication);
		when(this.authenticationManager.authenticate(any())).thenReturn(null);

		AuthenticationFilter filter = new AuthenticationFilter(this.authenticationManagerResolver, this.authenticationConverter);
		filter.setSuccessHandler(successHandler);

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		try {
			filter.doFilter(request, response, chain);
		} catch (ServletException e) {
			verifyZeroInteractions(this.successHandler);
			assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();

			throw e;
		}
	}

	@Test
	public void filterWhenNotMatchAndConvertAndAuthenticationSuccessThenContinues() throws Exception {
		when(this.requestMatcher.matches(any())).thenReturn(false);

		AuthenticationFilter filter = new AuthenticationFilter(this.authenticationManagerResolver, this.authenticationConverter);
		filter.setRequestMatcher(this.requestMatcher);

		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);

		verifyZeroInteractions(this.authenticationConverter, this.authenticationManagerResolver, this.successHandler);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	// gh-7446
	@Test
	public void filterWhenSuccessfulAuthenticationThenSessionIdChanges() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("test", "this", "ROLE_USER");
		when(this.authenticationConverter.convert(any())).thenReturn(authentication);
		when(this.authenticationManager.authenticate(any())).thenReturn(authentication);

		MockHttpSession session = new MockHttpSession();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		request.setSession(session);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = new MockFilterChain();

		String sessionId = session.getId();
		AuthenticationFilter filter = new AuthenticationFilter(this.authenticationManager, this.authenticationConverter);
		filter.doFilter(request, response, chain);

		assertThat(session.getId()).isNotEqualTo(sessionId);
	}

}
