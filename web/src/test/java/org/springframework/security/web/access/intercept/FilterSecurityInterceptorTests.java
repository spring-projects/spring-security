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

package org.springframework.security.web.access.intercept;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.event.AuthorizedEvent;
import org.springframework.security.access.intercept.AfterInvocationManager;
import org.springframework.security.access.intercept.RunAsManager;
import org.springframework.security.access.intercept.RunAsUserToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterInvocation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.springframework.security.web.servlet.TestMockHttpServletRequests.get;

/**
 * Tests {@link FilterSecurityInterceptor}.
 *
 * @author Ben Alex
 * @author Luke Taylor
 * @author Rob Winch
 */
public class FilterSecurityInterceptorTests {

	private AuthenticationManager am;

	private AccessDecisionManager adm;

	private FilterInvocationSecurityMetadataSource ods;

	private RunAsManager ram;

	private FilterSecurityInterceptor interceptor;

	private ApplicationEventPublisher publisher;

	@BeforeEach
	public final void setUp() {
		this.interceptor = new FilterSecurityInterceptor();
		this.am = mock(AuthenticationManager.class);
		this.ods = mock(FilterInvocationSecurityMetadataSource.class);
		this.adm = mock(AccessDecisionManager.class);
		this.ram = mock(RunAsManager.class);
		this.publisher = mock(ApplicationEventPublisher.class);
		this.interceptor.setAuthenticationManager(this.am);
		this.interceptor.setSecurityMetadataSource(this.ods);
		this.interceptor.setAccessDecisionManager(this.adm);
		this.interceptor.setRunAsManager(this.ram);
		this.interceptor.setApplicationEventPublisher(this.publisher);
		SecurityContextHolder.clearContext();
	}

	@AfterEach
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void testEnsuresAccessDecisionManagerSupportsFilterInvocationClass() throws Exception {
		given(this.adm.supports(FilterInvocation.class)).willReturn(true);
		assertThatIllegalArgumentException().isThrownBy(this.interceptor::afterPropertiesSet);
	}

	@Test
	public void testEnsuresRunAsManagerSupportsFilterInvocationClass() throws Exception {
		given(this.adm.supports(FilterInvocation.class)).willReturn(false);
		assertThatIllegalArgumentException().isThrownBy(this.interceptor::afterPropertiesSet);
	}

	/**
	 * We just test invocation works in a success event. There is no need to test access
	 * denied events as the abstract parent enforces that logic, which is extensively
	 * tested separately.
	 */
	@Test
	public void testSuccessfulInvocation() throws Throwable {
		// Setup a Context
		Authentication token = new TestingAuthenticationToken("Test", "Password", "NOT_USED");
		SecurityContextHolder.getContext().setAuthentication(token);
		FilterInvocation fi = createinvocation();
		given(this.ods.getAttributes(fi)).willReturn(SecurityConfig.createList("MOCK_OK"));
		this.interceptor.invoke(fi);
		// SEC-1697
		verify(this.publisher, never()).publishEvent(any(AuthorizedEvent.class));
	}

	@Test
	public void afterInvocationIsNotInvokedIfExceptionThrown() throws Exception {
		Authentication token = new TestingAuthenticationToken("Test", "Password", "NOT_USED");
		SecurityContextHolder.getContext().setAuthentication(token);
		FilterInvocation fi = createinvocation();
		FilterChain chain = fi.getChain();
		willThrow(new RuntimeException()).given(chain)
			.doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
		given(this.ods.getAttributes(fi)).willReturn(SecurityConfig.createList("MOCK_OK"));
		AfterInvocationManager aim = mock(AfterInvocationManager.class);
		this.interceptor.setAfterInvocationManager(aim);
		assertThatExceptionOfType(RuntimeException.class).isThrownBy(() -> this.interceptor.invoke(fi));
		verifyNoMoreInteractions(aim);
	}

	// SEC-1967
	@Test
	@SuppressWarnings("unchecked")
	public void finallyInvocationIsInvokedIfExceptionThrown() throws Exception {
		SecurityContext ctx = SecurityContextHolder.getContext();
		Authentication token = new TestingAuthenticationToken("Test", "Password", "NOT_USED");
		token.setAuthenticated(true);
		ctx.setAuthentication(token);
		RunAsManager runAsManager = mock(RunAsManager.class);
		given(runAsManager.buildRunAs(eq(token), any(), anyCollection()))
			.willReturn(new RunAsUserToken("key", "someone", "creds", token.getAuthorities(), token.getClass()));
		this.interceptor.setRunAsManager(runAsManager);
		FilterInvocation fi = createinvocation();
		FilterChain chain = fi.getChain();
		willThrow(new RuntimeException()).given(chain)
			.doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
		given(this.ods.getAttributes(fi)).willReturn(SecurityConfig.createList("MOCK_OK"));
		AfterInvocationManager aim = mock(AfterInvocationManager.class);
		this.interceptor.setAfterInvocationManager(aim);
		assertThatExceptionOfType(RuntimeException.class).isThrownBy(() -> this.interceptor.invoke(fi));
		// Check we've changed back
		assertThat(SecurityContextHolder.getContext()).isSameAs(ctx);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(token);
	}

	@Test
	// gh-4997
	public void doFilterWhenObserveOncePerRequestThenAttributeNotSet() throws Exception {
		this.interceptor.setObserveOncePerRequest(false);
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockHttpServletRequest request = new MockHttpServletRequest();
		this.interceptor.doFilter(request, response, new MockFilterChain());
		assertThat(request.getAttributeNames().hasMoreElements()).isFalse();
	}

	@Test
	public void doFilterWhenObserveOncePerRequestFalseAndInvokedTwiceThenObserveTwice() throws Throwable {
		Authentication token = new TestingAuthenticationToken("Test", "Password", "NOT_USED");
		SecurityContextHolder.getContext().setAuthentication(token);
		FilterInvocation fi = createinvocation();
		given(this.ods.getAttributes(fi)).willReturn(SecurityConfig.createList("MOCK_OK"));
		this.interceptor.invoke(fi);
		this.interceptor.invoke(fi);
		verify(this.adm, times(2)).decide(any(), any(), any());
	}

	private FilterInvocation createinvocation() {
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockHttpServletRequest request = get("/secure/page.html").build();
		FilterChain chain = mock(FilterChain.class);
		FilterInvocation fi = new FilterInvocation(request, response, chain);
		return fi;
	}

}
