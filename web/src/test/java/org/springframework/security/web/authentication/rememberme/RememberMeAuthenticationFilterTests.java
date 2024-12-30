/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.web.authentication.rememberme;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.SecurityContextRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests {@link RememberMeAuthenticationFilter}.
 *
 * @author Ben Alex
 */
public class RememberMeAuthenticationFilterTests {

	Authentication remembered = new TestingAuthenticationToken("remembered", "password", "ROLE_REMEMBERED");

	@BeforeEach
	public void setUp() {
		SecurityContextHolder.clearContext();
	}

	@AfterEach
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void testDetectsAuthenticationManagerProperty() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new RememberMeAuthenticationFilter(null, new NullRememberMeServices()));
	}

	@Test
	public void testDetectsRememberMeServicesProperty() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new RememberMeAuthenticationFilter(mock(AuthenticationManager.class), null));
	}

	@Test
	public void testOperationWhenAuthenticationExistsInContextHolder() throws Exception {
		// Put an Authentication object into the SecurityContextHolder
		Authentication originalAuth = new TestingAuthenticationToken("user", "password", "ROLE_A");
		SecurityContextHolder.getContext().setAuthentication(originalAuth);
		// Setup our filter correctly
		RememberMeAuthenticationFilter filter = new RememberMeAuthenticationFilter(mock(AuthenticationManager.class),
				new MockRememberMeServices(this.remembered));
		filter.afterPropertiesSet();
		// Test
		MockHttpServletRequest request = new MockHttpServletRequest();
		FilterChain fc = mock(FilterChain.class);
		request.setRequestURI("x");
		filter.doFilter(request, new MockHttpServletResponse(), fc);
		// Ensure filter didn't change our original object
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(originalAuth);
		verify(fc).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void testOperationWhenNoAuthenticationInContextHolder() throws Exception {
		AuthenticationManager am = mock(AuthenticationManager.class);
		given(am.authenticate(this.remembered)).willReturn(this.remembered);
		RememberMeAuthenticationFilter filter = new RememberMeAuthenticationFilter(am,
				new MockRememberMeServices(this.remembered));
		filter.afterPropertiesSet();
		MockHttpServletRequest request = new MockHttpServletRequest();
		FilterChain fc = mock(FilterChain.class);
		request.setRequestURI("x");
		filter.doFilter(request, new MockHttpServletResponse(), fc);
		// Ensure filter setup with our remembered authentication object
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(this.remembered);
		verify(fc).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void onUnsuccessfulLoginIsCalledWhenProviderRejectsAuth() throws Exception {
		final Authentication failedAuth = new TestingAuthenticationToken("failed", "");
		AuthenticationManager am = mock(AuthenticationManager.class);
		given(am.authenticate(any(Authentication.class))).willThrow(new BadCredentialsException(""));
		RememberMeAuthenticationFilter filter = new RememberMeAuthenticationFilter(am,
				new MockRememberMeServices(this.remembered)) {
			@Override
			protected void onUnsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
					AuthenticationException failed) {
				super.onUnsuccessfulAuthentication(request, response, failed);
				SecurityContextHolder.getContext().setAuthentication(failedAuth);
			}
		};
		filter.setApplicationEventPublisher(mock(ApplicationEventPublisher.class));
		filter.afterPropertiesSet();
		MockHttpServletRequest request = new MockHttpServletRequest();
		FilterChain fc = mock(FilterChain.class);
		request.setRequestURI("x");
		filter.doFilter(request, new MockHttpServletResponse(), fc);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(failedAuth);
		verify(fc).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void authenticationSuccessHandlerIsInvokedOnSuccessfulAuthenticationIfSet() throws Exception {
		AuthenticationManager am = mock(AuthenticationManager.class);
		given(am.authenticate(this.remembered)).willReturn(this.remembered);
		RememberMeAuthenticationFilter filter = new RememberMeAuthenticationFilter(am,
				new MockRememberMeServices(this.remembered));
		filter.setAuthenticationSuccessHandler(new SimpleUrlAuthenticationSuccessHandler("/target"));
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain fc = mock(FilterChain.class);
		request.setRequestURI("x");
		filter.doFilter(request, response, fc);
		assertThat(response.getRedirectedUrl()).isEqualTo("/target");
		// Should return after success handler is invoked, so chain should not proceed
		verifyNoMoreInteractions(fc);
	}

	@Test
	public void securityContextRepositoryInvokedIfSet() throws Exception {
		SecurityContextRepository securityContextRepository = mock(SecurityContextRepository.class);
		AuthenticationManager am = mock(AuthenticationManager.class);
		given(am.authenticate(this.remembered)).willReturn(this.remembered);
		RememberMeAuthenticationFilter filter = new RememberMeAuthenticationFilter(am,
				new MockRememberMeServices(this.remembered));
		filter.setAuthenticationSuccessHandler(new SimpleUrlAuthenticationSuccessHandler("/target"));
		filter.setSecurityContextRepository(securityContextRepository);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain fc = mock(FilterChain.class);
		request.setRequestURI("x");
		filter.doFilter(request, response, fc);
		verify(securityContextRepository).saveContext(any(), eq(request), eq(response));
	}

	@Test
	public void sessionAuthenticationStrategyInvokedIfSet() throws Exception {
		SessionAuthenticationStrategy sessionAuthenticationStrategy = mock(SessionAuthenticationStrategy.class);
		AuthenticationManager am = mock(AuthenticationManager.class);
		given(am.authenticate(this.remembered)).willReturn(this.remembered);
		RememberMeAuthenticationFilter filter = new RememberMeAuthenticationFilter(am,
				new MockRememberMeServices(this.remembered));
		filter.setAuthenticationSuccessHandler(new SimpleUrlAuthenticationSuccessHandler("/target"));
		filter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain fc = mock(FilterChain.class);
		request.setRequestURI("x");
		filter.doFilter(request, response, fc);
		verify(sessionAuthenticationStrategy).onAuthentication(any(), eq(request), eq(response));
	}

	private class MockRememberMeServices implements RememberMeServices {

		private Authentication authToReturn;

		MockRememberMeServices(Authentication authToReturn) {
			this.authToReturn = authToReturn;
		}

		@Override
		public Authentication autoLogin(HttpServletRequest request, HttpServletResponse response) {
			return this.authToReturn;
		}

		@Override
		public void loginFail(HttpServletRequest request, HttpServletResponse response) {
		}

		@Override
		public void loginSuccess(HttpServletRequest request, HttpServletResponse response,
				Authentication successfulAuthentication) {
		}

	}

}
