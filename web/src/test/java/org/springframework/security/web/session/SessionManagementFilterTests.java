/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.web.session;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;

import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.SecurityContextRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.withSettings;

/**
 * @author Luke Taylor
 * @author Rob Winch
 * @author Mark Chesney
 */
public class SessionManagementFilterTests {

	@BeforeEach
	@AfterEach
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void newSessionShouldNotBeCreatedIfSessionExistsAndUserIsNotAuthenticated() throws Exception {
		SecurityContextRepository repo = mock(SecurityContextRepository.class);
		SessionManagementFilter filter = new SessionManagementFilter(repo);
		HttpServletRequest request = new MockHttpServletRequest();
		String sessionId = request.getSession().getId();
		filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
		assertThat(request.getSession().getId()).isEqualTo(sessionId);
	}

	@Test
	public void strategyIsNotInvokedIfSecurityContextAlreadyExistsForRequest() throws Exception {
		SecurityContextRepository repo = mock(SecurityContextRepository.class);
		SessionAuthenticationStrategy strategy = mock(SessionAuthenticationStrategy.class);
		// mock that repo contains a security context
		given(repo.containsContext(any(HttpServletRequest.class))).willReturn(true);
		SessionManagementFilter filter = new SessionManagementFilter(repo, strategy);
		HttpServletRequest request = new MockHttpServletRequest();
		authenticateUser();
		filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
		verifyNoMoreInteractions(strategy);
	}

	@Test
	public void strategyIsNotInvokedIfAuthenticationIsNull() throws Exception {
		SecurityContextRepository repo = mock(SecurityContextRepository.class);
		SessionAuthenticationStrategy strategy = mock(SessionAuthenticationStrategy.class);
		SessionManagementFilter filter = new SessionManagementFilter(repo, strategy);
		HttpServletRequest request = new MockHttpServletRequest();
		filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
		verifyNoMoreInteractions(strategy);
	}

	@Test
	public void strategyIsInvokedIfUserIsNewlyAuthenticated() throws Exception {
		SecurityContextRepository repo = mock(SecurityContextRepository.class);
		// repo will return false to containsContext()
		SessionAuthenticationStrategy strategy = mock(SessionAuthenticationStrategy.class);
		SessionManagementFilter filter = new SessionManagementFilter(repo, strategy);
		HttpServletRequest request = new MockHttpServletRequest();
		authenticateUser();
		filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
		verify(strategy).onAuthentication(any(Authentication.class), any(HttpServletRequest.class),
				any(HttpServletResponse.class));
		// Check that it is only applied once to the request
		filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
		verifyNoMoreInteractions(strategy);
	}

	@Test
	public void strategyFailureInvokesFailureHandler() throws Exception {
		SecurityContextRepository repo = mock(SecurityContextRepository.class);
		// repo will return false to containsContext()
		SessionAuthenticationStrategy strategy = mock(SessionAuthenticationStrategy.class);
		AuthenticationFailureHandler failureHandler = mock(AuthenticationFailureHandler.class);
		SessionManagementFilter filter = new SessionManagementFilter(repo, strategy);
		filter.setAuthenticationFailureHandler(failureHandler);
		HttpServletRequest request = new MockHttpServletRequest();
		HttpServletResponse response = new MockHttpServletResponse();
		FilterChain fc = mock(FilterChain.class);
		authenticateUser();
		SessionAuthenticationException exception = new SessionAuthenticationException("Failure");
		willThrow(exception).given(strategy)
			.onAuthentication(SecurityContextHolder.getContext().getAuthentication(), request, response);
		filter.doFilter(request, response, fc);
		verifyNoMoreInteractions(fc);
		verify(failureHandler).onAuthenticationFailure(request, response, exception);
	}

	@Test
	public void responseIsRedirectedToTimeoutUrlIfSetAndSessionIsInvalid() throws Exception {
		SecurityContextRepository repo = mock(SecurityContextRepository.class);
		// repo will return false to containsContext()
		SessionAuthenticationStrategy strategy = mock(SessionAuthenticationStrategy.class);
		SessionManagementFilter filter = new SessionManagementFilter(repo, strategy);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestedSessionId("xxx");
		request.setRequestedSessionIdValid(false);
		MockHttpServletResponse response = new MockHttpServletResponse();
		filter.doFilter(request, response, new MockFilterChain());
		assertThat(response.getRedirectedUrl()).isNull();
		// Now set a redirect URL
		request = new MockHttpServletRequest();
		request.setRequestedSessionId("xxx");
		request.setRequestedSessionIdValid(false);
		SimpleRedirectInvalidSessionStrategy iss = new SimpleRedirectInvalidSessionStrategy("/timedOut");
		iss.setCreateNewSession(true);
		filter.setInvalidSessionStrategy(iss);
		FilterChain fc = mock(FilterChain.class);
		filter.doFilter(request, response, fc);
		verifyNoMoreInteractions(fc);
		assertThat(response.getRedirectedUrl()).isEqualTo("/timedOut");
	}

	@Test
	public void responseIsRedirectedToRequestedUrlIfSetAndSessionIsInvalid() throws Exception {
		SecurityContextRepository repo = mock(SecurityContextRepository.class);
		// repo will return false to containsContext()
		SessionAuthenticationStrategy strategy = mock(SessionAuthenticationStrategy.class);
		SessionManagementFilter filter = new SessionManagementFilter(repo, strategy);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestedSessionId("xxx");
		request.setRequestedSessionIdValid(false);
		MockHttpServletResponse response = new MockHttpServletResponse();
		filter.doFilter(request, response, new MockFilterChain());
		assertThat(response.getRedirectedUrl()).isNull();
		// Now set a redirect URL
		request = new MockHttpServletRequest();
		request.setRequestedSessionId("xxx");
		request.setRequestedSessionIdValid(false);
		request.setRequestURI("/requested");
		RequestedUrlRedirectInvalidSessionStrategy iss = new RequestedUrlRedirectInvalidSessionStrategy();
		iss.setCreateNewSession(true);
		filter.setInvalidSessionStrategy(iss);
		FilterChain fc = mock(FilterChain.class);
		filter.doFilter(request, response, fc);
		verifyNoMoreInteractions(fc);
		assertThat(response.getRedirectedUrl()).isEqualTo("/requested");
	}

	@Test
	public void responseIsRedirectedToRequestedUrlIfContextPathIsSetAndSessionIsInvalid() throws Exception {
		// given
		DefaultRedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
		redirectStrategy.setContextRelative(true);
		RequestedUrlRedirectInvalidSessionStrategy invalidSessionStrategy = new RequestedUrlRedirectInvalidSessionStrategy();
		invalidSessionStrategy.setCreateNewSession(true);
		invalidSessionStrategy.setRedirectStrategy(redirectStrategy);
		SecurityContextRepository securityContextRepository = mock(SecurityContextRepository.class);
		SessionAuthenticationStrategy sessionAuthenticationStrategy = mock(SessionAuthenticationStrategy.class);
		SessionManagementFilter filter = new SessionManagementFilter(securityContextRepository,
				sessionAuthenticationStrategy);
		filter.setInvalidSessionStrategy(invalidSessionStrategy);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setContextPath("/context");
		request.setRequestedSessionId("xxx");
		request.setRequestedSessionIdValid(false);
		request.setRequestURI("/context/requested");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);

		// when
		filter.doFilter(request, response, chain);

		// then
		verify(securityContextRepository).containsContext(request);
		verifyNoMoreInteractions(securityContextRepository, sessionAuthenticationStrategy, chain);
		assertThat(response.isCommitted()).isTrue();
		assertThat(response.getRedirectedUrl()).isEqualTo("/context/requested");
		assertThat(response.getStatus()).isEqualTo(302);
	}

	@Test
	public void responseIsRedirectedToRequestedUrlIfStatusCodeIsSetAndSessionIsInvalid() throws Exception {
		// given
		DefaultRedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
		redirectStrategy.setStatusCode(HttpStatus.TEMPORARY_REDIRECT);
		RequestedUrlRedirectInvalidSessionStrategy invalidSessionStrategy = new RequestedUrlRedirectInvalidSessionStrategy();
		invalidSessionStrategy.setCreateNewSession(true);
		invalidSessionStrategy.setRedirectStrategy(redirectStrategy);
		SecurityContextRepository securityContextRepository = mock(SecurityContextRepository.class);
		SessionAuthenticationStrategy sessionAuthenticationStrategy = mock(SessionAuthenticationStrategy.class);
		SessionManagementFilter filter = new SessionManagementFilter(securityContextRepository,
				sessionAuthenticationStrategy);
		filter.setInvalidSessionStrategy(invalidSessionStrategy);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestedSessionId("xxx");
		request.setRequestedSessionIdValid(false);
		request.setRequestURI("/requested");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);

		// when
		filter.doFilter(request, response, chain);

		// then
		verify(securityContextRepository).containsContext(request);
		verifyNoMoreInteractions(securityContextRepository, sessionAuthenticationStrategy, chain);
		assertThat(response.isCommitted()).isTrue();
		assertThat(response.getRedirectedUrl()).isEqualTo("/requested");
		assertThat(response.getStatus()).isEqualTo(307);
	}

	@Test
	public void customAuthenticationTrustResolver() throws Exception {
		AuthenticationTrustResolver trustResolver = mock(AuthenticationTrustResolver.class,
				withSettings().defaultAnswer(Answers.CALLS_REAL_METHODS));
		SecurityContextRepository repo = mock(SecurityContextRepository.class);
		SessionManagementFilter filter = new SessionManagementFilter(repo);
		filter.setTrustResolver(trustResolver);
		HttpServletRequest request = new MockHttpServletRequest();
		authenticateUser();
		filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
		verify(trustResolver).isAnonymous(any(Authentication.class));
	}

	@Test
	public void setTrustResolverNull() {
		SecurityContextRepository repo = mock(SecurityContextRepository.class);
		SessionManagementFilter filter = new SessionManagementFilter(repo);
		assertThatIllegalArgumentException().isThrownBy(() -> filter.setTrustResolver(null));
	}

	private void authenticateUser() {
		SecurityContextHolder.getContext()
			.setAuthentication(new TestingAuthenticationToken("user", "pass", "ROLE_USER"));
	}

}
