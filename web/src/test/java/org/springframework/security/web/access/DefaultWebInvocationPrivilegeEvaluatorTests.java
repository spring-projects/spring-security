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

package org.springframework.security.web.access;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.Before;
import org.junit.Test;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.intercept.RunAsManager;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

/**
 * Tests
 * {@link org.springframework.security.web.access.DefaultWebInvocationPrivilegeEvaluator}.
 *
 * @author Ben Alex
 */
public class DefaultWebInvocationPrivilegeEvaluatorTests {
	private AccessDecisionManager adm;
	private FilterInvocationSecurityMetadataSource ods;
	private RunAsManager ram;
	private FilterSecurityInterceptor interceptor;

	// ~ Methods
	// ========================================================================================================

	@Before
	public final void setUp() {
		interceptor = new FilterSecurityInterceptor();
		ods = mock(FilterInvocationSecurityMetadataSource.class);
		adm = mock(AccessDecisionManager.class);
		ram = mock(RunAsManager.class);
		interceptor.setAuthenticationManager(mock(AuthenticationManager.class));
		interceptor.setSecurityMetadataSource(ods);
		interceptor.setAccessDecisionManager(adm);
		interceptor.setRunAsManager(ram);
		interceptor.setApplicationEventPublisher(mock(ApplicationEventPublisher.class));
		SecurityContextHolder.clearContext();
	}

	@Test
	public void permitsAccessIfNoMatchingAttributesAndPublicInvocationsAllowed()
			throws Exception {
		DefaultWebInvocationPrivilegeEvaluator wipe = new DefaultWebInvocationPrivilegeEvaluator(
				interceptor);
		when(ods.getAttributes(anyObject())).thenReturn(null);
		assertThat(wipe.isAllowed("/context", "/foo/index.jsp", "GET",
				mock(Authentication.class))).isTrue();
	}

	@Test
	public void deniesAccessIfNoMatchingAttributesAndPublicInvocationsNotAllowed()
			throws Exception {
		DefaultWebInvocationPrivilegeEvaluator wipe = new DefaultWebInvocationPrivilegeEvaluator(
				interceptor);
		when(ods.getAttributes(anyObject())).thenReturn(null);
		interceptor.setRejectPublicInvocations(true);
		assertThat(wipe.isAllowed("/context", "/foo/index.jsp", "GET",
				mock(Authentication.class))).isFalse();
	}

	@Test
	public void deniesAccessIfAuthenticationIsNull() throws Exception {
		DefaultWebInvocationPrivilegeEvaluator wipe = new DefaultWebInvocationPrivilegeEvaluator(
				interceptor);
		assertThat(wipe.isAllowed("/foo/index.jsp", null)).isFalse();
	}

	@Test
	public void allowsAccessIfAccessDecisionManagerDoes() throws Exception {
		Authentication token = new TestingAuthenticationToken("test", "Password",
				"MOCK_INDEX");
		DefaultWebInvocationPrivilegeEvaluator wipe = new DefaultWebInvocationPrivilegeEvaluator(
				interceptor);
		assertThat(wipe.isAllowed("/foo/index.jsp", token)).isTrue();
	}

	@SuppressWarnings("unchecked")
	@Test
	public void deniesAccessIfAccessDecisionManagerDoes() throws Exception {
		Authentication token = new TestingAuthenticationToken("test", "Password",
				"MOCK_INDEX");
		DefaultWebInvocationPrivilegeEvaluator wipe = new DefaultWebInvocationPrivilegeEvaluator(
				interceptor);

		doThrow(new AccessDeniedException("")).when(adm).decide(
				any(Authentication.class), anyObject(), anyList());

		assertThat(wipe.isAllowed("/foo/index.jsp", token)).isFalse();
	}
}
