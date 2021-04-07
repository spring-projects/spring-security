/*
 * Copyright 2002-2021 the original author or authors.
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

import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;

import org.springframework.aop.Pointcut;
import org.springframework.aop.PointcutAdvisor;
import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.core.Ordered;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

/**
 * A {@link MethodInterceptor} which can determine if an {@link Authentication} has access
 * to the result of an {@link MethodInvocation} using an {@link AuthorizationManager}
 *
 * @author Evgeniy Cheban
 * @author Josh Cummings
 * @since 5.6
 */
public final class AuthorizationManagerAfterMethodInterceptor
		implements Ordered, MethodInterceptor, PointcutAdvisor, AopInfrastructureBean {

	static final Supplier<Authentication> AUTHENTICATION_SUPPLIER = () -> {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null) {
			throw new AuthenticationCredentialsNotFoundException(
					"An Authentication object was not found in the SecurityContext");
		}
		return authentication;
	};

	private final Pointcut pointcut;

	private final AuthorizationManager<MethodInvocationResult> authorizationManager;

	private int order;

	/**
	 * Creates an instance.
	 * @param pointcut the {@link Pointcut} to use
	 * @param authorizationManager the {@link AuthorizationManager} to use
	 */
	public AuthorizationManagerAfterMethodInterceptor(Pointcut pointcut,
			AuthorizationManager<MethodInvocationResult> authorizationManager) {
		Assert.notNull(pointcut, "pointcut cannot be null");
		Assert.notNull(authorizationManager, "authorizationManager cannot be null");
		this.pointcut = pointcut;
		this.authorizationManager = authorizationManager;
	}

	/**
	 * Creates an interceptor for the {@link PostAuthorize} annotation
	 * @return the interceptor
	 */
	public static AuthorizationManagerAfterMethodInterceptor postAuthorize() {
		return postAuthorize(new PostAuthorizeAuthorizationManager());
	}

	/**
	 * Creates an interceptor for the {@link PostAuthorize} annotation
	 * @param authorizationManager the {@link PostAuthorizeAuthorizationManager} to use
	 * @return the interceptor
	 */
	public static AuthorizationManagerAfterMethodInterceptor postAuthorize(
			PostAuthorizeAuthorizationManager authorizationManager) {
		AuthorizationManagerAfterMethodInterceptor interceptor = new AuthorizationManagerAfterMethodInterceptor(
				AuthorizationMethodPointcuts.forAnnotations(PostAuthorize.class), authorizationManager);
		interceptor.setOrder(500);
		return interceptor;
	}

	/**
	 * Determine if an {@link Authentication} has access to the {@link MethodInvocation}
	 * using the {@link AuthorizationManager}.
	 * @param mi the {@link MethodInvocation} to check
	 * @throws AccessDeniedException if access is not granted
	 */
	@Override
	public Object invoke(MethodInvocation mi) throws Throwable {
		Object result = mi.proceed();
		this.authorizationManager.verify(AUTHENTICATION_SUPPLIER, new MethodInvocationResult(mi, result));
		return result;
	}

	@Override
	public int getOrder() {
		return this.order;
	}

	public void setOrder(int order) {
		this.order = order;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Pointcut getPointcut() {
		return this.pointcut;
	}

	@Override
	public Advice getAdvice() {
		return this;
	}

	@Override
	public boolean isPerInstance() {
		return true;
	}

}
