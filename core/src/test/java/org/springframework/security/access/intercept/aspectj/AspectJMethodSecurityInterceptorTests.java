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

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

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

import java.lang.reflect.Method;
import java.util.List;

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
		token = new TestingAuthenticationToken("Test", "Password");
		interceptor = new AspectJMethodSecurityInterceptor();
		interceptor.setAccessDecisionManager(adm);
		interceptor.setAuthenticationManager(authman);
		interceptor.setSecurityMetadataSource(mds);
		// Set up joinpoint information for the countLength method on TargetObject
		joinPoint = mock(ProceedingJoinPoint.class); // new MockJoinPoint(new
														// TargetObject(), method);
		Signature sig = mock(Signature.class);
		when(sig.getDeclaringType()).thenReturn(TargetObject.class);
		JoinPoint.StaticPart staticPart = mock(JoinPoint.StaticPart.class);
		when(joinPoint.getSignature()).thenReturn(sig);
		when(joinPoint.getStaticPart()).thenReturn(staticPart);
		CodeSignature codeSig = mock(CodeSignature.class);
		when(codeSig.getName()).thenReturn("countLength");
		when(codeSig.getDeclaringType()).thenReturn(TargetObject.class);
		when(codeSig.getParameterTypes()).thenReturn(new Class[] { String.class });
		when(staticPart.getSignature()).thenReturn(codeSig);
		when(mds.getAttributes(any())).thenReturn(SecurityConfig.createList("ROLE_USER"));
		when(authman.authenticate(token)).thenReturn(token);
	}

	@After
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void callbackIsInvokedWhenPermissionGranted() throws Throwable {
		SecurityContextHolder.getContext().setAuthentication(token);
		interceptor.invoke(joinPoint, aspectJCallback);
		verify(aspectJCallback).proceedWithObject();

		// Just try the other method too
		interceptor.invoke(joinPoint);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void callbackIsNotInvokedWhenPermissionDenied() {
		doThrow(new AccessDeniedException("denied")).when(adm).decide(any(), any(), any());

		SecurityContextHolder.getContext().setAuthentication(token);
		try {
			interceptor.invoke(joinPoint, aspectJCallback);
			fail("Expected AccessDeniedException");
		}
		catch (AccessDeniedException expected) {
		}
		verify(aspectJCallback, never()).proceedWithObject();
	}

	@Test
	public void adapterHoldsCorrectData() {
		TargetObject to = new TargetObject();
		Method m = ClassUtils.getMethodIfAvailable(TargetObject.class, "countLength", new Class[] { String.class });

		when(joinPoint.getTarget()).thenReturn(to);
		when(joinPoint.getArgs()).thenReturn(new Object[] { "Hi" });
		MethodInvocationAdapter mia = new MethodInvocationAdapter(joinPoint);
		assertThat(mia.getArguments()[0]).isEqualTo("Hi");
		assertThat(mia.getStaticPart()).isEqualTo(m);
		assertThat(mia.getMethod()).isEqualTo(m);
		assertThat(mia.getThis()).isSameAs(to);
	}

	@Test
	public void afterInvocationManagerIsNotInvokedIfExceptionIsRaised() {
		token.setAuthenticated(true);
		SecurityContextHolder.getContext().setAuthentication(token);

		AfterInvocationManager aim = mock(AfterInvocationManager.class);
		interceptor.setAfterInvocationManager(aim);

		when(aspectJCallback.proceedWithObject()).thenThrow(new RuntimeException());

		try {
			interceptor.invoke(joinPoint, aspectJCallback);
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
		ctx.setAuthentication(token);
		token.setAuthenticated(true);
		final RunAsManager runAs = mock(RunAsManager.class);
		final RunAsUserToken runAsToken = new RunAsUserToken("key", "someone", "creds", token.getAuthorities(),
				TestingAuthenticationToken.class);
		interceptor.setRunAsManager(runAs);
		when(runAs.buildRunAs(eq(token), any(MethodInvocation.class), any(List.class))).thenReturn(runAsToken);
		when(aspectJCallback.proceedWithObject()).thenThrow(new RuntimeException());

		try {
			interceptor.invoke(joinPoint, aspectJCallback);
			fail("Expected Exception");
		}
		catch (RuntimeException success) {
		}

		// Check we've changed back
		assertThat(SecurityContextHolder.getContext()).isSameAs(ctx);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(token);
	}

	// SEC-1967
	@Test
	@SuppressWarnings("unchecked")
	public void invokeRunAsReplacementCleansAfterException() throws Throwable {
		SecurityContext ctx = SecurityContextHolder.getContext();
		ctx.setAuthentication(token);
		token.setAuthenticated(true);
		final RunAsManager runAs = mock(RunAsManager.class);
		final RunAsUserToken runAsToken = new RunAsUserToken("key", "someone", "creds", token.getAuthorities(),
				TestingAuthenticationToken.class);
		interceptor.setRunAsManager(runAs);
		when(runAs.buildRunAs(eq(token), any(MethodInvocation.class), any(List.class))).thenReturn(runAsToken);
		when(joinPoint.proceed()).thenThrow(new RuntimeException());

		try {
			interceptor.invoke(joinPoint);
			fail("Expected Exception");
		}
		catch (RuntimeException success) {
		}

		// Check we've changed back
		assertThat(SecurityContextHolder.getContext()).isSameAs(ctx);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(token);
	}

}
