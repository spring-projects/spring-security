/*
 * Copyright 2004, 2005, 2006, 2021 Acegi Technology Pty Limited
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

package org.springframework.security.web.servletapi;

import java.util.Arrays;
import java.util.List;

import jakarta.servlet.AsyncContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.concurrent.DelegatingSecurityContextRunnable;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests {@link SecurityContextHolderAwareRequestFilter}.
 *
 * @author Ben Alex
 * @author Rob Winch
 * @author Eddú Meléndez
 */
@ExtendWith(MockitoExtension.class)
public class SecurityContextHolderAwareRequestFilterTests {

	@Captor
	private ArgumentCaptor<HttpServletRequest> requestCaptor;

	@Mock
	private AuthenticationManager authenticationManager;

	@Mock
	private AuthenticationEntryPoint authenticationEntryPoint;

	@Mock
	private LogoutHandler logoutHandler;

	@Mock
	private FilterChain filterChain;

	@Mock
	private HttpServletRequest request;

	@Mock
	private HttpServletResponse response;

	private List<LogoutHandler> logoutHandlers;

	private SecurityContextHolderAwareRequestFilter filter;

	@BeforeEach
	public void setUp() throws Exception {
		this.logoutHandlers = Arrays.asList(this.logoutHandler);
		this.filter = new SecurityContextHolderAwareRequestFilter();
		this.filter.setAuthenticationEntryPoint(this.authenticationEntryPoint);
		this.filter.setAuthenticationManager(this.authenticationManager);
		this.filter.setLogoutHandlers(this.logoutHandlers);
		this.filter.afterPropertiesSet();
	}

	@AfterEach
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void expectedRequestWrapperClassIsUsed() throws Exception {
		this.filter.setRolePrefix("ROLE_");
		this.filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), this.filterChain);
		// Now re-execute the filter, ensuring our replacement wrapper is still used
		this.filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), this.filterChain);
		verify(this.filterChain, times(2)).doFilter(any(SecurityContextHolderAwareRequestWrapper.class),
				any(HttpServletResponse.class));
		this.filter.destroy();
	}

	@Test
	public void authenticateFalse() throws Exception {
		assertThat(wrappedRequest().authenticate(this.response)).isFalse();
		verify(this.authenticationEntryPoint).commence(eq(this.requestCaptor.getValue()), eq(this.response),
				any(AuthenticationException.class));
		verifyNoMoreInteractions(this.authenticationManager, this.logoutHandler);
		verify(this.request, times(0)).authenticate(any(HttpServletResponse.class));
	}

	@Test
	public void authenticateTrue() throws Exception {
		SecurityContextHolder.getContext()
				.setAuthentication(new TestingAuthenticationToken("test", "password", "ROLE_USER"));
		assertThat(wrappedRequest().authenticate(this.response)).isTrue();
		verifyNoMoreInteractions(this.authenticationEntryPoint, this.authenticationManager, this.logoutHandler);
		verify(this.request, times(0)).authenticate(any(HttpServletResponse.class));
	}

	@Test
	public void authenticateNullEntryPointFalse() throws Exception {
		this.filter.setAuthenticationEntryPoint(null);
		this.filter.afterPropertiesSet();
		assertThat(wrappedRequest().authenticate(this.response)).isFalse();
		verify(this.request).authenticate(this.response);
		verifyNoMoreInteractions(this.authenticationEntryPoint, this.authenticationManager, this.logoutHandler);
	}

	@Test
	public void authenticateNullEntryPointTrue() throws Exception {
		given(this.request.authenticate(this.response)).willReturn(true);
		this.filter.setAuthenticationEntryPoint(null);
		this.filter.afterPropertiesSet();
		assertThat(wrappedRequest().authenticate(this.response)).isTrue();
		verify(this.request).authenticate(this.response);
		verifyNoMoreInteractions(this.authenticationEntryPoint, this.authenticationManager, this.logoutHandler);
	}

	@Test
	public void login() throws Exception {
		TestingAuthenticationToken expectedAuth = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		given(this.authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
				.willReturn(expectedAuth);
		wrappedRequest().login(expectedAuth.getName(), String.valueOf(expectedAuth.getCredentials()));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(expectedAuth);
		verifyNoMoreInteractions(this.authenticationEntryPoint, this.logoutHandler);
		verify(this.request, times(0)).login(anyString(), anyString());
	}

	// SEC-2296
	@Test
	public void loginWithExistingUser() throws Exception {
		TestingAuthenticationToken expectedAuth = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		SecurityContextHolder.getContext().setAuthentication(expectedAuth);
		assertThatExceptionOfType(ServletException.class).isThrownBy(
				() -> wrappedRequest().login(expectedAuth.getName(), String.valueOf(expectedAuth.getCredentials())));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(expectedAuth);
		verifyNoMoreInteractions(this.authenticationEntryPoint, this.logoutHandler);
		verify(this.request, times(0)).login(anyString(), anyString());
	}

	@Test
	public void loginFail() throws Exception {
		AuthenticationException authException = new BadCredentialsException("Invalid");
		given(this.authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
				.willThrow(authException);
		assertThatExceptionOfType(ServletException.class)
				.isThrownBy(() -> wrappedRequest().login("invalid", "credentials")).withCause(authException);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		verifyNoMoreInteractions(this.authenticationEntryPoint, this.logoutHandler);
		verify(this.request, times(0)).login(anyString(), anyString());
	}

	@Test
	public void loginNullAuthenticationManager() throws Exception {
		this.filter.setAuthenticationManager(null);
		this.filter.afterPropertiesSet();
		String username = "username";
		String password = "password";
		wrappedRequest().login(username, password);
		verify(this.request).login(username, password);
		verifyNoMoreInteractions(this.authenticationEntryPoint, this.authenticationManager, this.logoutHandler);
	}

	@Test
	public void loginNullAuthenticationManagerFail() throws Exception {
		this.filter.setAuthenticationManager(null);
		this.filter.afterPropertiesSet();
		String username = "username";
		String password = "password";
		ServletException authException = new ServletException("Failed Login");
		willThrow(authException).given(this.request).login(username, password);
		assertThatExceptionOfType(ServletException.class).isThrownBy(() -> wrappedRequest().login(username, password))
				.isEqualTo(authException);
		verifyNoMoreInteractions(this.authenticationEntryPoint, this.authenticationManager, this.logoutHandler);
	}

	@Test
	public void loginWhenHttpServletRequestHasAuthenticationDetailsThenAuthenticationRequestHasDetails()
			throws Exception {
		String ipAddress = "10.0.0.100";
		String sessionId = "session-id";
		given(this.request.getRemoteAddr()).willReturn(ipAddress);
		given(this.request.getSession(anyBoolean())).willReturn(new MockHttpSession(null, sessionId));
		wrappedRequest().login("username", "password");

		ArgumentCaptor<UsernamePasswordAuthenticationToken> authenticationCaptor = ArgumentCaptor
				.forClass(UsernamePasswordAuthenticationToken.class);
		verify(this.authenticationManager).authenticate(authenticationCaptor.capture());

		UsernamePasswordAuthenticationToken authenticationRequest = authenticationCaptor.getValue();
		assertThat(authenticationRequest.getDetails()).isInstanceOf(WebAuthenticationDetails.class);

		WebAuthenticationDetails details = (WebAuthenticationDetails) authenticationRequest.getDetails();
		assertThat(details.getRemoteAddress()).isEqualTo(ipAddress);
		assertThat(details.getSessionId()).isEqualTo(sessionId);
	}

	@Test
	public void logout() throws Exception {
		TestingAuthenticationToken expectedAuth = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		SecurityContextHolder.getContext().setAuthentication(expectedAuth);
		HttpServletRequest wrappedRequest = wrappedRequest();
		wrappedRequest.logout();
		verify(this.logoutHandler).logout(wrappedRequest, this.response, expectedAuth);
		verifyNoMoreInteractions(this.authenticationManager, this.logoutHandler);
		verify(this.request, times(0)).logout();
	}

	@Test
	public void logoutNullLogoutHandler() throws Exception {
		this.filter.setLogoutHandlers(null);
		this.filter.afterPropertiesSet();
		wrappedRequest().logout();
		verify(this.request).logout();
		verifyNoMoreInteractions(this.authenticationEntryPoint, this.authenticationManager, this.logoutHandler);
	}

	// gh-3780
	@Test
	public void getAsyncContextNullFromSuper() throws Exception {
		assertThat(wrappedRequest().getAsyncContext()).isNull();
	}

	@Test
	public void getAsyncContextStart() throws Exception {
		ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);
		SecurityContext context = SecurityContextHolder.createEmptyContext();
		TestingAuthenticationToken expectedAuth = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		context.setAuthentication(expectedAuth);
		SecurityContextHolder.setContext(context);
		AsyncContext asyncContext = mock(AsyncContext.class);
		given(this.request.getAsyncContext()).willReturn(asyncContext);
		Runnable runnable = () -> {
		};
		wrappedRequest().getAsyncContext().start(runnable);
		verifyNoMoreInteractions(this.authenticationManager, this.logoutHandler);
		verify(asyncContext).start(runnableCaptor.capture());
		DelegatingSecurityContextRunnable wrappedRunnable = (DelegatingSecurityContextRunnable) runnableCaptor
				.getValue();
		assertThat(ReflectionTestUtils.getField(wrappedRunnable, "delegateSecurityContext")).isEqualTo(context);
		assertThat(ReflectionTestUtils.getField(wrappedRunnable, "delegate"));
	}

	@Test
	public void startAsyncStart() throws Exception {
		ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);
		SecurityContext context = SecurityContextHolder.createEmptyContext();
		TestingAuthenticationToken expectedAuth = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		context.setAuthentication(expectedAuth);
		SecurityContextHolder.setContext(context);
		AsyncContext asyncContext = mock(AsyncContext.class);
		given(this.request.startAsync()).willReturn(asyncContext);
		Runnable runnable = () -> {
		};
		wrappedRequest().startAsync().start(runnable);
		verifyNoMoreInteractions(this.authenticationManager, this.logoutHandler);
		verify(asyncContext).start(runnableCaptor.capture());
		DelegatingSecurityContextRunnable wrappedRunnable = (DelegatingSecurityContextRunnable) runnableCaptor
				.getValue();
		assertThat(ReflectionTestUtils.getField(wrappedRunnable, "delegateSecurityContext")).isEqualTo(context);
		assertThat(ReflectionTestUtils.getField(wrappedRunnable, "delegate"));
	}

	@Test
	public void startAsyncWithRequestResponseStart() throws Exception {
		ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);
		SecurityContext context = SecurityContextHolder.createEmptyContext();
		TestingAuthenticationToken expectedAuth = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		context.setAuthentication(expectedAuth);
		SecurityContextHolder.setContext(context);
		AsyncContext asyncContext = mock(AsyncContext.class);
		given(this.request.startAsync(this.request, this.response)).willReturn(asyncContext);
		Runnable runnable = () -> {
		};
		wrappedRequest().startAsync(this.request, this.response).start(runnable);
		verifyNoMoreInteractions(this.authenticationManager, this.logoutHandler);
		verify(asyncContext).start(runnableCaptor.capture());
		DelegatingSecurityContextRunnable wrappedRunnable = (DelegatingSecurityContextRunnable) runnableCaptor
				.getValue();
		assertThat(ReflectionTestUtils.getField(wrappedRunnable, "delegateSecurityContext")).isEqualTo(context);
		assertThat(ReflectionTestUtils.getField(wrappedRunnable, "delegate"));
	}

	// SEC-3047
	@Test
	public void updateRequestFactory() throws Exception {
		SecurityContextHolder.getContext()
				.setAuthentication(new TestingAuthenticationToken("user", "password", "PREFIX_USER"));
		this.filter.setRolePrefix("PREFIX_");
		assertThat(wrappedRequest().isUserInRole("PREFIX_USER")).isTrue();
	}

	private HttpServletRequest wrappedRequest() throws Exception {
		this.filter.doFilter(this.request, this.response, this.filterChain);
		verify(this.filterChain).doFilter(this.requestCaptor.capture(), any(HttpServletResponse.class));
		return this.requestCaptor.getValue();
	}

}
