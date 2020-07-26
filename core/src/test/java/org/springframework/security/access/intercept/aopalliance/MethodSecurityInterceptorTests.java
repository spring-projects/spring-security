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

package org.springframework.security.access.intercept.aopalliance;

import java.util.List;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.springframework.aop.framework.ProxyFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.ITargetObject;
import org.springframework.security.TargetObject;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.event.AuthorizationFailureEvent;
import org.springframework.security.access.event.AuthorizedEvent;
import org.springframework.security.access.intercept.AfterInvocationManager;
import org.springframework.security.access.intercept.RunAsManager;
import org.springframework.security.access.intercept.RunAsUserToken;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

/**
 * Tests {@link MethodSecurityInterceptor}.
 *
 * @author Ben Alex
 * @author Rob Winch
 */
@SuppressWarnings("unchecked")
public class MethodSecurityInterceptorTests {

	private TestingAuthenticationToken token;

	private MethodSecurityInterceptor interceptor;

	private ITargetObject realTarget;

	private ITargetObject advisedTarget;

	private AccessDecisionManager adm;

	private MethodSecurityMetadataSource mds;

	private AuthenticationManager authman;

	private ApplicationEventPublisher eventPublisher;

	@Before
	public final void setUp() {
		SecurityContextHolder.clearContext();
		this.token = new TestingAuthenticationToken("Test", "Password");
		this.interceptor = new MethodSecurityInterceptor();
		this.adm = mock(AccessDecisionManager.class);
		this.authman = mock(AuthenticationManager.class);
		this.mds = mock(MethodSecurityMetadataSource.class);
		this.eventPublisher = mock(ApplicationEventPublisher.class);
		this.interceptor.setAccessDecisionManager(this.adm);
		this.interceptor.setAuthenticationManager(this.authman);
		this.interceptor.setSecurityMetadataSource(this.mds);
		this.interceptor.setApplicationEventPublisher(this.eventPublisher);
		createTarget(false);
	}

	@After
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	private void createTarget(boolean useMock) {
		this.realTarget = useMock ? mock(ITargetObject.class) : new TargetObject();
		ProxyFactory pf = new ProxyFactory(this.realTarget);
		pf.addAdvice(this.interceptor);
		this.advisedTarget = (ITargetObject) pf.getProxy();
	}

	@Test
	public void gettersReturnExpectedData() {
		RunAsManager runAs = mock(RunAsManager.class);
		AfterInvocationManager aim = mock(AfterInvocationManager.class);
		this.interceptor.setRunAsManager(runAs);
		this.interceptor.setAfterInvocationManager(aim);
		assertThat(this.interceptor.getAccessDecisionManager()).isEqualTo(this.adm);
		assertThat(this.interceptor.getRunAsManager()).isEqualTo(runAs);
		assertThat(this.interceptor.getAuthenticationManager()).isEqualTo(this.authman);
		assertThat(this.interceptor.getSecurityMetadataSource()).isEqualTo(this.mds);
		assertThat(this.interceptor.getAfterInvocationManager()).isEqualTo(aim);
	}

	@Test(expected = IllegalArgumentException.class)
	public void missingAccessDecisionManagerIsDetected() throws Exception {
		this.interceptor.setAccessDecisionManager(null);
		this.interceptor.afterPropertiesSet();
	}

	@Test(expected = IllegalArgumentException.class)
	public void missingAuthenticationManagerIsDetected() throws Exception {
		this.interceptor.setAuthenticationManager(null);
		this.interceptor.afterPropertiesSet();
	}

	@Test(expected = IllegalArgumentException.class)
	public void missingMethodSecurityMetadataSourceIsRejected() throws Exception {
		this.interceptor.setSecurityMetadataSource(null);
		this.interceptor.afterPropertiesSet();
	}

	@Test(expected = IllegalArgumentException.class)
	public void missingRunAsManagerIsRejected() throws Exception {
		this.interceptor.setRunAsManager(null);
		this.interceptor.afterPropertiesSet();
	}

	@Test(expected = IllegalArgumentException.class)
	public void initializationRejectsSecurityMetadataSourceThatDoesNotSupportMethodInvocation() throws Throwable {
		when(this.mds.supports(MethodInvocation.class)).thenReturn(false);
		this.interceptor.afterPropertiesSet();
	}

	@Test(expected = IllegalArgumentException.class)
	public void initializationRejectsAccessDecisionManagerThatDoesNotSupportMethodInvocation() throws Exception {
		when(this.mds.supports(MethodInvocation.class)).thenReturn(true);
		when(this.adm.supports(MethodInvocation.class)).thenReturn(false);
		this.interceptor.afterPropertiesSet();
	}

	@Test(expected = IllegalArgumentException.class)
	public void intitalizationRejectsRunAsManagerThatDoesNotSupportMethodInvocation() throws Exception {
		final RunAsManager ram = mock(RunAsManager.class);
		when(ram.supports(MethodInvocation.class)).thenReturn(false);
		this.interceptor.setRunAsManager(ram);
		this.interceptor.afterPropertiesSet();
	}

	@Test(expected = IllegalArgumentException.class)
	public void intitalizationRejectsAfterInvocationManagerThatDoesNotSupportMethodInvocation() throws Exception {
		final AfterInvocationManager aim = mock(AfterInvocationManager.class);
		when(aim.supports(MethodInvocation.class)).thenReturn(false);
		this.interceptor.setAfterInvocationManager(aim);
		this.interceptor.afterPropertiesSet();
	}

	@Test(expected = IllegalArgumentException.class)
	public void initializationFailsIfAccessDecisionManagerRejectsConfigAttributes() throws Exception {
		when(this.adm.supports(any(ConfigAttribute.class))).thenReturn(false);
		this.interceptor.afterPropertiesSet();
	}

	@Test
	public void validationNotAttemptedIfIsValidateConfigAttributesSetToFalse() throws Exception {
		when(this.adm.supports(MethodInvocation.class)).thenReturn(true);
		when(this.mds.supports(MethodInvocation.class)).thenReturn(true);
		this.interceptor.setValidateConfigAttributes(false);
		this.interceptor.afterPropertiesSet();
		verify(this.mds, never()).getAllConfigAttributes();
		verify(this.adm, never()).supports(any(ConfigAttribute.class));
	}

	@Test
	public void validationNotAttemptedIfMethodSecurityMetadataSourceReturnsNullForAttributes() throws Exception {
		when(this.adm.supports(MethodInvocation.class)).thenReturn(true);
		when(this.mds.supports(MethodInvocation.class)).thenReturn(true);
		when(this.mds.getAllConfigAttributes()).thenReturn(null);

		this.interceptor.setValidateConfigAttributes(true);
		this.interceptor.afterPropertiesSet();
		verify(this.adm, never()).supports(any(ConfigAttribute.class));
	}

	@Test
	public void callingAPublicMethodFacadeWillNotRepeatSecurityChecksWhenPassedToTheSecuredMethodItFronts() {
		mdsReturnsNull();
		String result = this.advisedTarget.publicMakeLowerCase("HELLO");
		assertThat(result).isEqualTo("hello Authentication empty");
	}

	@Test
	public void callingAPublicMethodWhenPresentingAnAuthenticationObjectDoesntChangeItsAuthenticatedProperty() {
		mdsReturnsNull();
		SecurityContextHolder.getContext().setAuthentication(this.token);
		assertThat(this.advisedTarget.publicMakeLowerCase("HELLO"))
				.isEqualTo("hello org.springframework.security.authentication.TestingAuthenticationToken false");
		assertThat(!this.token.isAuthenticated()).isTrue();
	}

	@Test(expected = AuthenticationException.class)
	public void callIsntMadeWhenAuthenticationManagerRejectsAuthentication() {
		final TestingAuthenticationToken token = new TestingAuthenticationToken("Test", "Password");
		SecurityContextHolder.getContext().setAuthentication(token);

		mdsReturnsUserRole();
		when(this.authman.authenticate(token)).thenThrow(new BadCredentialsException("rejected"));

		this.advisedTarget.makeLowerCase("HELLO");
	}

	@Test
	public void callSucceedsIfAccessDecisionManagerGrantsAccess() {
		this.token.setAuthenticated(true);
		this.interceptor.setPublishAuthorizationSuccess(true);
		SecurityContextHolder.getContext().setAuthentication(this.token);
		mdsReturnsUserRole();

		String result = this.advisedTarget.makeLowerCase("HELLO");

		// Note we check the isAuthenticated remained true in following line
		assertThat(result)
				.isEqualTo("hello org.springframework.security.authentication.TestingAuthenticationToken true");
		verify(this.eventPublisher).publishEvent(any(AuthorizedEvent.class));
	}

	@Test
	public void callIsntMadeWhenAccessDecisionManagerRejectsAccess() {
		SecurityContextHolder.getContext().setAuthentication(this.token);
		// Use mocked target to make sure invocation doesn't happen (not in expectations
		// so test would fail)
		createTarget(true);
		mdsReturnsUserRole();
		when(this.authman.authenticate(this.token)).thenReturn(this.token);
		doThrow(new AccessDeniedException("rejected")).when(this.adm).decide(any(Authentication.class),
				any(MethodInvocation.class), any(List.class));

		try {
			this.advisedTarget.makeUpperCase("HELLO");
			fail("Expected Exception");
		}
		catch (AccessDeniedException expected) {
		}
		verify(this.eventPublisher).publishEvent(any(AuthorizationFailureEvent.class));
	}

	@Test(expected = IllegalArgumentException.class)
	public void rejectsNullSecuredObjects() throws Throwable {
		this.interceptor.invoke(null);
	}

	@Test
	public void runAsReplacementIsCorrectlySet() {
		SecurityContext ctx = SecurityContextHolder.getContext();
		ctx.setAuthentication(this.token);
		this.token.setAuthenticated(true);
		final RunAsManager runAs = mock(RunAsManager.class);
		final RunAsUserToken runAsToken = new RunAsUserToken("key", "someone", "creds", this.token.getAuthorities(),
				TestingAuthenticationToken.class);
		this.interceptor.setRunAsManager(runAs);
		mdsReturnsUserRole();
		when(runAs.buildRunAs(eq(this.token), any(MethodInvocation.class), any(List.class))).thenReturn(runAsToken);

		String result = this.advisedTarget.makeUpperCase("hello");
		assertThat(result).isEqualTo("HELLO org.springframework.security.access.intercept.RunAsUserToken true");
		// Check we've changed back
		assertThat(SecurityContextHolder.getContext()).isSameAs(ctx);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(this.token);
	}

	// SEC-1967
	@Test
	public void runAsReplacementCleansAfterException() {
		createTarget(true);
		when(this.realTarget.makeUpperCase(anyString())).thenThrow(new RuntimeException());
		SecurityContext ctx = SecurityContextHolder.getContext();
		ctx.setAuthentication(this.token);
		this.token.setAuthenticated(true);
		final RunAsManager runAs = mock(RunAsManager.class);
		final RunAsUserToken runAsToken = new RunAsUserToken("key", "someone", "creds", this.token.getAuthorities(),
				TestingAuthenticationToken.class);
		this.interceptor.setRunAsManager(runAs);
		mdsReturnsUserRole();
		when(runAs.buildRunAs(eq(this.token), any(MethodInvocation.class), any(List.class))).thenReturn(runAsToken);

		try {
			this.advisedTarget.makeUpperCase("hello");
			fail("Expected Exception");
		}
		catch (RuntimeException success) {
		}

		// Check we've changed back
		assertThat(SecurityContextHolder.getContext()).isSameAs(ctx);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(this.token);
	}

	@Test(expected = AuthenticationCredentialsNotFoundException.class)
	public void emptySecurityContextIsRejected() {
		mdsReturnsUserRole();
		this.advisedTarget.makeUpperCase("hello");
	}

	@Test
	public void afterInvocationManagerIsNotInvokedIfExceptionIsRaised() throws Throwable {
		MethodInvocation mi = mock(MethodInvocation.class);
		this.token.setAuthenticated(true);
		SecurityContextHolder.getContext().setAuthentication(this.token);
		mdsReturnsUserRole();

		AfterInvocationManager aim = mock(AfterInvocationManager.class);
		this.interceptor.setAfterInvocationManager(aim);

		when(mi.proceed()).thenThrow(new Throwable());

		try {
			this.interceptor.invoke(mi);
			fail("Expected exception");
		}
		catch (Throwable expected) {
		}

		verifyZeroInteractions(aim);
	}

	void mdsReturnsNull() {
		when(this.mds.getAttributes(any(MethodInvocation.class))).thenReturn(null);
	}

	void mdsReturnsUserRole() {
		when(this.mds.getAttributes(any(MethodInvocation.class))).thenReturn(SecurityConfig.createList("ROLE_USER"));
	}

}
