/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.authorization.method;

import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.Test;

import org.springframework.aop.Pointcut;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link AuthorizationManagerAfterMethodInterceptor}.
 *
 * @author Evgeniy Cheban
 * @author Gengwu Zhao
 */
public class AuthorizationManagerAfterMethodInterceptorTests {

	@Test
	public void instantiateWhenMethodMatcherNullThenException() {
		AuthorizationManager<MethodInvocationResult> mockAuthorizationManager = mock(AuthorizationManager.class);
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new AuthorizationManagerAfterMethodInterceptor(null, mockAuthorizationManager))
			.withMessage("pointcut cannot be null");
	}

	@Test
	public void instantiateWhenAuthorizationManagerNullThenException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new AuthorizationManagerAfterMethodInterceptor(mock(Pointcut.class), null))
			.withMessage("authorizationManager cannot be null");
	}

	@Test
	public void beforeWhenMockAuthorizationManagerThenCheckAndReturnedObject() throws Throwable {
		MethodInvocation mockMethodInvocation = mock(MethodInvocation.class);
		MethodInvocationResult result = new MethodInvocationResult(mockMethodInvocation, new Object());
		given(mockMethodInvocation.proceed()).willReturn(result.getResult());
		AuthorizationManager<MethodInvocationResult> mockAuthorizationManager = mock(AuthorizationManager.class);
		given(mockAuthorizationManager.authorize(any(), any())).willCallRealMethod();
		AuthorizationManagerAfterMethodInterceptor advice = new AuthorizationManagerAfterMethodInterceptor(
				Pointcut.TRUE, mockAuthorizationManager);
		Object returnedObject = advice.invoke(mockMethodInvocation);
		assertThat(returnedObject).isEqualTo(result.getResult());
		verify(mockAuthorizationManager).check(any(Supplier.class), any(MethodInvocationResult.class));
	}

	@Test
	public void afterWhenMockSecurityContextHolderStrategyThenUses() throws Throwable {
		Authentication authentication = TestAuthentication.authenticatedUser();
		SecurityContextHolderStrategy strategy = mockSecurityContextHolderStrategy(
				new SecurityContextImpl(authentication));
		MethodInvocation invocation = mock(MethodInvocation.class);
		AuthorizationManager<MethodInvocationResult> authorizationManager = AuthenticatedAuthorizationManager
			.authenticated();
		AuthorizationManagerAfterMethodInterceptor advice = new AuthorizationManagerAfterMethodInterceptor(
				Pointcut.TRUE, authorizationManager);
		advice.setSecurityContextHolderStrategy(strategy);
		advice.invoke(invocation);
		verify(strategy).getContext();
	}

	// gh-12877
	@Test
	public void afterWhenStaticSecurityContextHolderStrategyAfterConstructorThenUses() throws Throwable {
		Authentication authentication = new TestingAuthenticationToken("john", "password",
				AuthorityUtils.createAuthorityList("authority"));
		SecurityContextHolderStrategy strategy = mockSecurityContextHolderStrategy(
				new SecurityContextImpl(authentication));
		MethodInvocation invocation = mock(MethodInvocation.class);
		AuthorizationManager<MethodInvocationResult> authorizationManager = AuthenticatedAuthorizationManager
			.authenticated();
		AuthorizationManagerAfterMethodInterceptor advice = new AuthorizationManagerAfterMethodInterceptor(
				Pointcut.TRUE, authorizationManager);
		SecurityContextHolderStrategy saved = SecurityContextHolder.getContextHolderStrategy();
		SecurityContextHolder.setContextHolderStrategy(strategy);
		advice.invoke(invocation);
		verify(strategy).getContext();
		SecurityContextHolder.setContextHolderStrategy(saved);
	}

	@Test
	public void configureWhenAuthorizationEventPublisherIsNullThenIllegalArgument() {
		AuthorizationManagerAfterMethodInterceptor advice = new AuthorizationManagerAfterMethodInterceptor(
				Pointcut.TRUE, AuthenticatedAuthorizationManager.authenticated());
		assertThatIllegalArgumentException().isThrownBy(() -> advice.setAuthorizationEventPublisher(null))
			.withMessage("eventPublisher cannot be null");
	}

	@Test
	public void invokeWhenAuthorizationEventPublisherThenUses() throws Throwable {
		AuthorizationManagerAfterMethodInterceptor advice = new AuthorizationManagerAfterMethodInterceptor(
				Pointcut.TRUE, AuthenticatedAuthorizationManager.authenticated());
		AuthorizationEventPublisher eventPublisher = mock(AuthorizationEventPublisher.class);
		doCallRealMethod().when(eventPublisher)
			.publishAuthorizationEvent(any(Supplier.class), any(), any(AuthorizationResult.class));
		advice.setAuthorizationEventPublisher(eventPublisher);

		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"));
		SecurityContextHolder.setContext(securityContext);

		MethodInvocation mockMethodInvocation = mock(MethodInvocation.class);
		MethodInvocationResult result = new MethodInvocationResult(mockMethodInvocation, new Object());
		given(mockMethodInvocation.proceed()).willReturn(result.getResult());

		advice.invoke(mockMethodInvocation);
		verify(eventPublisher).publishAuthorizationEvent(any(Supplier.class), any(MethodInvocationResult.class),
				any(AuthorizationDecision.class));
	}

	@Test
	public void invokeWhenCustomAuthorizationDeniedExceptionThenThrows() throws Throwable {
		MethodInvocation mi = mock(MethodInvocation.class);
		given(mi.proceed()).willReturn("ok");
		AuthorizationManager<MethodInvocationResult> manager = mock(AuthorizationManager.class);
		given(manager.check(any(), any()))
			.willThrow(new MyAuthzDeniedException("denied", new AuthorizationDecision(false)));
		given(manager.authorize(any(), any())).willCallRealMethod();
		AuthorizationManagerAfterMethodInterceptor advice = new AuthorizationManagerAfterMethodInterceptor(
				Pointcut.TRUE, manager);
		assertThatExceptionOfType(MyAuthzDeniedException.class).isThrownBy(() -> advice.invoke(mi));
	}

	private SecurityContextHolderStrategy mockSecurityContextHolderStrategy(SecurityContextImpl securityContextImpl) {
		SecurityContextHolderStrategy strategy = mock(SecurityContextHolderStrategy.class);
		given(strategy.getContext()).willReturn(securityContextImpl);
		return strategy;
	}

	static class MyAuthzDeniedException extends AuthorizationDeniedException {

		MyAuthzDeniedException(String msg, AuthorizationResult authorizationResult) {
			super(msg, authorizationResult);
		}

	}

}
