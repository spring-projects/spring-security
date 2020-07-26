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

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

/**
 * Tests {@link RememberMeAuthenticationFilter}.
 *
 * @author Ben Alex
 */
public class RememberMeAuthenticationFilterTests {

	Authentication remembered = new TestingAuthenticationToken("remembered", "password", "ROLE_REMEMBERED");

	@Before
	public void setUp() {
		SecurityContextHolder.clearContext();
	}

	@After
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test(expected = IllegalArgumentException.class)
	public void testDetectsAuthenticationManagerProperty() {
		new RememberMeAuthenticationFilter(null, new NullRememberMeServices());
	}

	@Test(expected = IllegalArgumentException.class)
	public void testDetectsRememberMeServicesProperty() {
		new RememberMeAuthenticationFilter(mock(AuthenticationManager.class), null);
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
		when(am.authenticate(this.remembered)).thenReturn(this.remembered);

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
		when(am.authenticate(any(Authentication.class))).thenThrow(new BadCredentialsException(""));

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
		when(am.authenticate(this.remembered)).thenReturn(this.remembered);
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
		verifyZeroInteractions(fc);
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
