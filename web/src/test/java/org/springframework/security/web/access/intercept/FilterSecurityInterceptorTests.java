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

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

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
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

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

	@Before
	public final void setUp() {
		interceptor = new FilterSecurityInterceptor();
		am = mock(AuthenticationManager.class);
		ods = mock(FilterInvocationSecurityMetadataSource.class);
		adm = mock(AccessDecisionManager.class);
		ram = mock(RunAsManager.class);
		publisher = mock(ApplicationEventPublisher.class);
		interceptor.setAuthenticationManager(am);
		interceptor.setSecurityMetadataSource(ods);
		interceptor.setAccessDecisionManager(adm);
		interceptor.setRunAsManager(ram);
		interceptor.setApplicationEventPublisher(publisher);
		SecurityContextHolder.clearContext();
	}

	@After
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test(expected = IllegalArgumentException.class)
	public void testEnsuresAccessDecisionManagerSupportsFilterInvocationClass() throws Exception {
		when(adm.supports(FilterInvocation.class)).thenReturn(true);
		interceptor.afterPropertiesSet();
	}

	@Test(expected = IllegalArgumentException.class)
	public void testEnsuresRunAsManagerSupportsFilterInvocationClass() throws Exception {
		when(adm.supports(FilterInvocation.class)).thenReturn(false);
		interceptor.afterPropertiesSet();
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

		when(ods.getAttributes(fi)).thenReturn(SecurityConfig.createList("MOCK_OK"));

		interceptor.invoke(fi);

		// SEC-1697
		verify(publisher, never()).publishEvent(any(AuthorizedEvent.class));
	}

	@Test
	public void afterInvocationIsNotInvokedIfExceptionThrown() throws Exception {
		Authentication token = new TestingAuthenticationToken("Test", "Password", "NOT_USED");
		SecurityContextHolder.getContext().setAuthentication(token);

		FilterInvocation fi = createinvocation();
		FilterChain chain = fi.getChain();

		doThrow(new RuntimeException()).when(chain).doFilter(any(HttpServletRequest.class),
				any(HttpServletResponse.class));
		when(ods.getAttributes(fi)).thenReturn(SecurityConfig.createList("MOCK_OK"));

		AfterInvocationManager aim = mock(AfterInvocationManager.class);
		interceptor.setAfterInvocationManager(aim);

		try {
			interceptor.invoke(fi);
			fail("Expected exception");
		}
		catch (RuntimeException expected) {
		}

		verifyZeroInteractions(aim);
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
		when(runAsManager.buildRunAs(eq(token), any(), anyCollection()))
				.thenReturn(new RunAsUserToken("key", "someone", "creds", token.getAuthorities(), token.getClass()));
		interceptor.setRunAsManager(runAsManager);

		FilterInvocation fi = createinvocation();
		FilterChain chain = fi.getChain();

		doThrow(new RuntimeException()).when(chain).doFilter(any(HttpServletRequest.class),
				any(HttpServletResponse.class));
		when(ods.getAttributes(fi)).thenReturn(SecurityConfig.createList("MOCK_OK"));

		AfterInvocationManager aim = mock(AfterInvocationManager.class);
		interceptor.setAfterInvocationManager(aim);

		try {
			interceptor.invoke(fi);
			fail("Expected exception");
		}
		catch (RuntimeException expected) {
		}

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

	private FilterInvocation createinvocation() {
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServletPath("/secure/page.html");

		FilterChain chain = mock(FilterChain.class);
		FilterInvocation fi = new FilterInvocation(request, response, chain);

		return fi;
	}

}
