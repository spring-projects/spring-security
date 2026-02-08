/*
 * Copyright 2004-present the original author or authors.
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

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.BDDMockito;
import org.mockito.Mockito;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.intercept.RunAsManager;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

/**
 * Tests
 * {@link org.springframework.security.web.access.DefaultWebInvocationPrivilegeEvaluator}.
 *
 * @author Ben Alex
 */
@SuppressWarnings("deprecation")
public class DefaultWebInvocationPrivilegeEvaluatorTests {

	private AccessDecisionManager adm;

	private FilterInvocationSecurityMetadataSource ods;

	private RunAsManager ram;

	private FilterSecurityInterceptor interceptor;

	@BeforeEach
	public final void setUp() {
		this.interceptor = new FilterSecurityInterceptor();
		this.ods = Mockito.mock(FilterInvocationSecurityMetadataSource.class);
		this.adm = Mockito.mock(AccessDecisionManager.class);
		this.ram = Mockito.mock(RunAsManager.class);
		this.interceptor.setAuthenticationManager(Mockito.mock(AuthenticationManager.class));
		this.interceptor.setSecurityMetadataSource(this.ods);
		this.interceptor.setAccessDecisionManager(this.adm);
		this.interceptor.setRunAsManager(this.ram);
		this.interceptor.setApplicationEventPublisher(Mockito.mock(ApplicationEventPublisher.class));
		SecurityContextHolder.clearContext();
	}

	@Test
	public void permitsAccessIfNoMatchingAttributesAndPublicInvocationsAllowed() {
		DefaultWebInvocationPrivilegeEvaluator wipe = new DefaultWebInvocationPrivilegeEvaluator(this.interceptor);
		BDDMockito.given(this.ods.getAttributes(ArgumentMatchers.any())).willReturn(null);
		Assertions.assertThat(wipe.isAllowed("/context", "/foo/index.jsp", "GET", Mockito.mock(Authentication.class)))
			.isTrue();
	}

	@Test
	public void deniesAccessIfNoMatchingAttributesAndPublicInvocationsNotAllowed() {
		DefaultWebInvocationPrivilegeEvaluator wipe = new DefaultWebInvocationPrivilegeEvaluator(this.interceptor);
		BDDMockito.given(this.ods.getAttributes(ArgumentMatchers.any())).willReturn(null);
		this.interceptor.setRejectPublicInvocations(true);
		Assertions.assertThat(wipe.isAllowed("/context", "/foo/index.jsp", "GET", Mockito.mock(Authentication.class)))
			.isFalse();
	}

	@Test
	public void deniesAccessIfAuthenticationIsNull() {
		DefaultWebInvocationPrivilegeEvaluator wipe = new DefaultWebInvocationPrivilegeEvaluator(this.interceptor);
		Assertions.assertThat(wipe.isAllowed("/foo/index.jsp", null)).isFalse();
	}

	@Test
	public void allowsAccessIfAccessDecisionManagerDoes() {
		Authentication token = new TestingAuthenticationToken("test", "Password", "MOCK_INDEX");
		DefaultWebInvocationPrivilegeEvaluator wipe = new DefaultWebInvocationPrivilegeEvaluator(this.interceptor);
		Assertions.assertThat(wipe.isAllowed("/foo/index.jsp", token)).isTrue();
	}

	@SuppressWarnings("unchecked")
	@Test
	public void deniesAccessIfAccessDecisionManagerDoes() {
		Authentication token = new TestingAuthenticationToken("test", "Password", "MOCK_INDEX");
		DefaultWebInvocationPrivilegeEvaluator wipe = new DefaultWebInvocationPrivilegeEvaluator(this.interceptor);
		BDDMockito.willThrow(new AccessDeniedException(""))
			.given(this.adm)
			.decide(ArgumentMatchers.any(Authentication.class), ArgumentMatchers.any(), ArgumentMatchers.anyList());
		Assertions.assertThat(wipe.isAllowed("/foo/index.jsp", token)).isFalse();
	}

	@Test
	public void isAllowedWhenServletContextIsSetThenPassedFilterInvocationHasServletContext() {
		Authentication token = new TestingAuthenticationToken("test", "Password", "MOCK_INDEX");
		MockServletContext servletContext = new MockServletContext();
		ArgumentCaptor<FilterInvocation> filterInvocationArgumentCaptor = ArgumentCaptor
			.forClass(FilterInvocation.class);
		DefaultWebInvocationPrivilegeEvaluator wipe = new DefaultWebInvocationPrivilegeEvaluator(this.interceptor);
		wipe.setServletContext(servletContext);
		wipe.isAllowed("/foo/index.jsp", token);
		Mockito.verify(this.adm)
			.decide(ArgumentMatchers.eq(token), filterInvocationArgumentCaptor.capture(), ArgumentMatchers.any());
		Assertions.assertThat(filterInvocationArgumentCaptor.getValue().getRequest().getServletContext()).isNotNull();
	}

}
