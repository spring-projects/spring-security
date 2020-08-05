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
		token = new TestingAuthenticationToken("Test", "Password");
		interceptor = new MethodSecurityInterceptor();
		adm = mock(AccessDecisionManager.class);
		authman = mock(AuthenticationManager.class);
		mds = mock(MethodSecurityMetadataSource.class);
		eventPublisher = mock(ApplicationEventPublisher.class);
		interceptor.setAccessDecisionManager(adm);
		interceptor.setAuthenticationManager(authman);
		interceptor.setSecurityMetadataSource(mds);
		interceptor.setApplicationEventPublisher(eventPublisher);
		createTarget(false);
	}

	@After
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	private void createTarget(boolean useMock) {
		realTarget = useMock ? mock(ITargetObject.class) : new TargetObject();
		ProxyFactory pf = new ProxyFactory(realTarget);
		pf.addAdvice(interceptor);
		advisedTarget = (ITargetObject) pf.getProxy();
	}

	@Test
	public void gettersReturnExpectedData() {
		RunAsManager runAs = mock(RunAsManager.class);
		AfterInvocationManager aim = mock(AfterInvocationManager.class);
		interceptor.setRunAsManager(runAs);
		interceptor.setAfterInvocationManager(aim);
		assertThat(interceptor.getAccessDecisionManager()).isEqualTo(adm);
		assertThat(interceptor.getRunAsManager()).isEqualTo(runAs);
		assertThat(interceptor.getAuthenticationManager()).isEqualTo(authman);
		assertThat(interceptor.getSecurityMetadataSource()).isEqualTo(mds);
		assertThat(interceptor.getAfterInvocationManager()).isEqualTo(aim);
	}

	@Test(expected = IllegalArgumentException.class)
	public void missingAccessDecisionManagerIsDetected() throws Exception {
		interceptor.setAccessDecisionManager(null);
		interceptor.afterPropertiesSet();
	}

	@Test(expected = IllegalArgumentException.class)
	public void missingAuthenticationManagerIsDetected() throws Exception {
		interceptor.setAuthenticationManager(null);
		interceptor.afterPropertiesSet();
	}

	@Test(expected = IllegalArgumentException.class)
	public void missingMethodSecurityMetadataSourceIsRejected() throws Exception {
		interceptor.setSecurityMetadataSource(null);
		interceptor.afterPropertiesSet();
	}

	@Test(expected = IllegalArgumentException.class)
	public void missingRunAsManagerIsRejected() throws Exception {
		interceptor.setRunAsManager(null);
		interceptor.afterPropertiesSet();
	}

	@Test(expected = IllegalArgumentException.class)
	public void initializationRejectsSecurityMetadataSourceThatDoesNotSupportMethodInvocation() throws Throwable {
		when(mds.supports(MethodInvocation.class)).thenReturn(false);
		interceptor.afterPropertiesSet();
	}

	@Test(expected = IllegalArgumentException.class)
	public void initializationRejectsAccessDecisionManagerThatDoesNotSupportMethodInvocation() throws Exception {
		when(mds.supports(MethodInvocation.class)).thenReturn(true);
		when(adm.supports(MethodInvocation.class)).thenReturn(false);
		interceptor.afterPropertiesSet();
	}

	@Test(expected = IllegalArgumentException.class)
	public void intitalizationRejectsRunAsManagerThatDoesNotSupportMethodInvocation() throws Exception {
		final RunAsManager ram = mock(RunAsManager.class);
		when(ram.supports(MethodInvocation.class)).thenReturn(false);
		interceptor.setRunAsManager(ram);
		interceptor.afterPropertiesSet();
	}

	@Test(expected = IllegalArgumentException.class)
	public void intitalizationRejectsAfterInvocationManagerThatDoesNotSupportMethodInvocation() throws Exception {
		final AfterInvocationManager aim = mock(AfterInvocationManager.class);
		when(aim.supports(MethodInvocation.class)).thenReturn(false);
		interceptor.setAfterInvocationManager(aim);
		interceptor.afterPropertiesSet();
	}

	@Test(expected = IllegalArgumentException.class)
	public void initializationFailsIfAccessDecisionManagerRejectsConfigAttributes() throws Exception {
		when(adm.supports(any(ConfigAttribute.class))).thenReturn(false);
		interceptor.afterPropertiesSet();
	}

	@Test
	public void validationNotAttemptedIfIsValidateConfigAttributesSetToFalse() throws Exception {
		when(adm.supports(MethodInvocation.class)).thenReturn(true);
		when(mds.supports(MethodInvocation.class)).thenReturn(true);
		interceptor.setValidateConfigAttributes(false);
		interceptor.afterPropertiesSet();
		verify(mds, never()).getAllConfigAttributes();
		verify(adm, never()).supports(any(ConfigAttribute.class));
	}

	@Test
	public void validationNotAttemptedIfMethodSecurityMetadataSourceReturnsNullForAttributes() throws Exception {
		when(adm.supports(MethodInvocation.class)).thenReturn(true);
		when(mds.supports(MethodInvocation.class)).thenReturn(true);
		when(mds.getAllConfigAttributes()).thenReturn(null);

		interceptor.setValidateConfigAttributes(true);
		interceptor.afterPropertiesSet();
		verify(adm, never()).supports(any(ConfigAttribute.class));
	}

	@Test
	public void callingAPublicMethodFacadeWillNotRepeatSecurityChecksWhenPassedToTheSecuredMethodItFronts() {
		mdsReturnsNull();
		String result = advisedTarget.publicMakeLowerCase("HELLO");
		assertThat(result).isEqualTo("hello Authentication empty");
	}

	@Test
	public void callingAPublicMethodWhenPresentingAnAuthenticationObjectDoesntChangeItsAuthenticatedProperty() {
		mdsReturnsNull();
		SecurityContextHolder.getContext().setAuthentication(token);
		assertThat(advisedTarget.publicMakeLowerCase("HELLO"))
				.isEqualTo("hello org.springframework.security.authentication.TestingAuthenticationToken false");
		assertThat(!token.isAuthenticated()).isTrue();
	}

	@Test(expected = AuthenticationException.class)
	public void callIsntMadeWhenAuthenticationManagerRejectsAuthentication() {
		final TestingAuthenticationToken token = new TestingAuthenticationToken("Test", "Password");
		SecurityContextHolder.getContext().setAuthentication(token);

		mdsReturnsUserRole();
		when(authman.authenticate(token)).thenThrow(new BadCredentialsException("rejected"));

		advisedTarget.makeLowerCase("HELLO");
	}

	@Test
	public void callSucceedsIfAccessDecisionManagerGrantsAccess() {
		token.setAuthenticated(true);
		interceptor.setPublishAuthorizationSuccess(true);
		SecurityContextHolder.getContext().setAuthentication(token);
		mdsReturnsUserRole();

		String result = advisedTarget.makeLowerCase("HELLO");

		// Note we check the isAuthenticated remained true in following line
		assertThat(result)
				.isEqualTo("hello org.springframework.security.authentication.TestingAuthenticationToken true");
		verify(eventPublisher).publishEvent(any(AuthorizedEvent.class));
	}

	@Test
	public void callIsntMadeWhenAccessDecisionManagerRejectsAccess() {
		SecurityContextHolder.getContext().setAuthentication(token);
		// Use mocked target to make sure invocation doesn't happen (not in expectations
		// so test would fail)
		createTarget(true);
		mdsReturnsUserRole();
		when(authman.authenticate(token)).thenReturn(token);
		doThrow(new AccessDeniedException("rejected")).when(adm).decide(any(Authentication.class),
				any(MethodInvocation.class), any(List.class));

		try {
			advisedTarget.makeUpperCase("HELLO");
			fail("Expected Exception");
		}
		catch (AccessDeniedException expected) {
		}
		verify(eventPublisher).publishEvent(any(AuthorizationFailureEvent.class));
	}

	@Test(expected = IllegalArgumentException.class)
	public void rejectsNullSecuredObjects() throws Throwable {
		interceptor.invoke(null);
	}

	@Test
	public void runAsReplacementIsCorrectlySet() {
		SecurityContext ctx = SecurityContextHolder.getContext();
		ctx.setAuthentication(token);
		token.setAuthenticated(true);
		final RunAsManager runAs = mock(RunAsManager.class);
		final RunAsUserToken runAsToken = new RunAsUserToken("key", "someone", "creds", token.getAuthorities(),
				TestingAuthenticationToken.class);
		interceptor.setRunAsManager(runAs);
		mdsReturnsUserRole();
		when(runAs.buildRunAs(eq(token), any(MethodInvocation.class), any(List.class))).thenReturn(runAsToken);

		String result = advisedTarget.makeUpperCase("hello");
		assertThat(result).isEqualTo("HELLO org.springframework.security.access.intercept.RunAsUserToken true");
		// Check we've changed back
		assertThat(SecurityContextHolder.getContext()).isSameAs(ctx);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(token);
	}

	// SEC-1967
	@Test
	public void runAsReplacementCleansAfterException() {
		createTarget(true);
		when(realTarget.makeUpperCase(anyString())).thenThrow(new RuntimeException());
		SecurityContext ctx = SecurityContextHolder.getContext();
		ctx.setAuthentication(token);
		token.setAuthenticated(true);
		final RunAsManager runAs = mock(RunAsManager.class);
		final RunAsUserToken runAsToken = new RunAsUserToken("key", "someone", "creds", token.getAuthorities(),
				TestingAuthenticationToken.class);
		interceptor.setRunAsManager(runAs);
		mdsReturnsUserRole();
		when(runAs.buildRunAs(eq(token), any(MethodInvocation.class), any(List.class))).thenReturn(runAsToken);

		try {
			advisedTarget.makeUpperCase("hello");
			fail("Expected Exception");
		}
		catch (RuntimeException success) {
		}

		// Check we've changed back
		assertThat(SecurityContextHolder.getContext()).isSameAs(ctx);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(token);
	}

	@Test(expected = AuthenticationCredentialsNotFoundException.class)
	public void emptySecurityContextIsRejected() {
		mdsReturnsUserRole();
		advisedTarget.makeUpperCase("hello");
	}

	@Test
	public void afterInvocationManagerIsNotInvokedIfExceptionIsRaised() throws Throwable {
		MethodInvocation mi = mock(MethodInvocation.class);
		token.setAuthenticated(true);
		SecurityContextHolder.getContext().setAuthentication(token);
		mdsReturnsUserRole();

		AfterInvocationManager aim = mock(AfterInvocationManager.class);
		interceptor.setAfterInvocationManager(aim);

		when(mi.proceed()).thenThrow(new Throwable());

		try {
			interceptor.invoke(mi);
			fail("Expected exception");
		}
		catch (Throwable expected) {
		}

		verifyZeroInteractions(aim);
	}

	void mdsReturnsNull() {
		when(mds.getAttributes(any(MethodInvocation.class))).thenReturn(null);
	}

	void mdsReturnsUserRole() {
		when(mds.getAttributes(any(MethodInvocation.class))).thenReturn(SecurityConfig.createList("ROLE_USER"));
	}

}
