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

package org.springframework.security.access.intercept.aspectj;

import java.lang.reflect.Method;
import java.util.List;

import org.aopalliance.intercept.MethodInvocation;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.Signature;
import org.aspectj.lang.reflect.CodeSignature;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import org.springframework.security.TargetObject;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.intercept.AfterInvocationManager;
import org.springframework.security.access.intercept.RunAsManager;
import org.springframework.security.access.intercept.RunAsUserToken;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.ClassUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;

/**
 * Tests {@link AspectJMethodSecurityInterceptor}.
 *
 * @author Ben Alex
 * @author Luke Taylor
 * @author Rob Winch
 */
public class AspectJMethodSecurityInterceptorTests {

	private TestingAuthenticationToken token;

	private AspectJMethodSecurityInterceptor interceptor;

	private @Mock AccessDecisionManager adm;

	private @Mock MethodSecurityMetadataSource mds;

	private @Mock AuthenticationManager authman;

	private @Mock AspectJCallback aspectJCallback;

	private ProceedingJoinPoint joinPoint;

	@Before
	public final void setUp() {
		MockitoAnnotations.initMocks(this);
		SecurityContextHolder.clearContext();
		this.token = new TestingAuthenticationToken("Test", "Password");
		this.interceptor = new AspectJMethodSecurityInterceptor();
		this.interceptor.setAccessDecisionManager(this.adm);
		this.interceptor.setAuthenticationManager(this.authman);
		this.interceptor.setSecurityMetadataSource(this.mds);
		// Set up joinpoint information for the countLength method on TargetObject
		this.joinPoint = mock(ProceedingJoinPoint.class); // new MockJoinPoint(new
															// TargetObject(), method);
		Signature sig = mock(Signature.class);
		given(sig.getDeclaringType()).willReturn(TargetObject.class);
		JoinPoint.StaticPart staticPart = mock(JoinPoint.StaticPart.class);
		given(this.joinPoint.getSignature()).willReturn(sig);
		given(this.joinPoint.getStaticPart()).willReturn(staticPart);
		CodeSignature codeSig = mock(CodeSignature.class);
		given(codeSig.getName()).willReturn("countLength");
		given(codeSig.getDeclaringType()).willReturn(TargetObject.class);
		given(codeSig.getParameterTypes()).willReturn(new Class[] { String.class });
		given(staticPart.getSignature()).willReturn(codeSig);
		given(this.mds.getAttributes(any())).willReturn(SecurityConfig.createList("ROLE_USER"));
		given(this.authman.authenticate(this.token)).willReturn(this.token);
	}

	@After
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void callbackIsInvokedWhenPermissionGranted() throws Throwable {
		SecurityContextHolder.getContext().setAuthentication(this.token);
		this.interceptor.invoke(this.joinPoint, this.aspectJCallback);
		verify(this.aspectJCallback).proceedWithObject();
		// Just try the other method too
		this.interceptor.invoke(this.joinPoint);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void callbackIsNotInvokedWhenPermissionDenied() {
		willThrow(new AccessDeniedException("denied")).given(this.adm).decide(any(), any(), any());
		SecurityContextHolder.getContext().setAuthentication(this.token);
		try {
			this.interceptor.invoke(this.joinPoint, this.aspectJCallback);
			fail("Expected AccessDeniedException");
		}
		catch (AccessDeniedException expected) {
		}
		verify(this.aspectJCallback, never()).proceedWithObject();
	}

	@Test
	public void adapterHoldsCorrectData() {
		TargetObject to = new TargetObject();
		Method m = ClassUtils.getMethodIfAvailable(TargetObject.class, "countLength", new Class[] { String.class });
		given(this.joinPoint.getTarget()).willReturn(to);
		given(this.joinPoint.getArgs()).willReturn(new Object[] { "Hi" });
		MethodInvocationAdapter mia = new MethodInvocationAdapter(this.joinPoint);
		assertThat(mia.getArguments()[0]).isEqualTo("Hi");
		assertThat(mia.getStaticPart()).isEqualTo(m);
		assertThat(mia.getMethod()).isEqualTo(m);
		assertThat(mia.getThis()).isSameAs(to);
	}

	@Test
	public void afterInvocationManagerIsNotInvokedIfExceptionIsRaised() {
		this.token.setAuthenticated(true);
		SecurityContextHolder.getContext().setAuthentication(this.token);
		AfterInvocationManager aim = mock(AfterInvocationManager.class);
		this.interceptor.setAfterInvocationManager(aim);
		given(this.aspectJCallback.proceedWithObject()).willThrow(new RuntimeException());
		try {
			this.interceptor.invoke(this.joinPoint, this.aspectJCallback);
			fail("Expected exception");
		}
		catch (RuntimeException expected) {
		}
		verifyZeroInteractions(aim);
	}

	// SEC-1967
	@Test
	@SuppressWarnings("unchecked")
	public void invokeWithAspectJCallbackRunAsReplacementCleansAfterException() {
		SecurityContext ctx = SecurityContextHolder.getContext();
		ctx.setAuthentication(this.token);
		this.token.setAuthenticated(true);
		final RunAsManager runAs = mock(RunAsManager.class);
		final RunAsUserToken runAsToken = new RunAsUserToken("key", "someone", "creds", this.token.getAuthorities(),
				TestingAuthenticationToken.class);
		this.interceptor.setRunAsManager(runAs);
		given(runAs.buildRunAs(eq(this.token), any(MethodInvocation.class), any(List.class))).willReturn(runAsToken);
		given(this.aspectJCallback.proceedWithObject()).willThrow(new RuntimeException());
		try {
			this.interceptor.invoke(this.joinPoint, this.aspectJCallback);
			fail("Expected Exception");
		}
		catch (RuntimeException success) {
		}
		// Check we've changed back
		assertThat(SecurityContextHolder.getContext()).isSameAs(ctx);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(this.token);
	}

	// SEC-1967
	@Test
	@SuppressWarnings("unchecked")
	public void invokeRunAsReplacementCleansAfterException() throws Throwable {
		SecurityContext ctx = SecurityContextHolder.getContext();
		ctx.setAuthentication(this.token);
		this.token.setAuthenticated(true);
		final RunAsManager runAs = mock(RunAsManager.class);
		final RunAsUserToken runAsToken = new RunAsUserToken("key", "someone", "creds", this.token.getAuthorities(),
				TestingAuthenticationToken.class);
		this.interceptor.setRunAsManager(runAs);
		given(runAs.buildRunAs(eq(this.token), any(MethodInvocation.class), any(List.class))).willReturn(runAsToken);
		given(this.joinPoint.proceed()).willThrow(new RuntimeException());
		try {
			this.interceptor.invoke(this.joinPoint);
			fail("Expected Exception");
		}
		catch (RuntimeException success) {
		}
		// Check we've changed back
		assertThat(SecurityContextHolder.getContext()).isSameAs(ctx);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(this.token);
	}

}
