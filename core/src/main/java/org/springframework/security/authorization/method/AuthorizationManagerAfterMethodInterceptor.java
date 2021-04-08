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

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.aop.Pointcut;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * An {@link AuthorizationMethodInterceptor} which can determine if an
 * {@link Authentication} has access to the result of an {@link MethodInvocation} using an
 * {@link AuthorizationManager}
 *
 * @author Evgeniy Cheban
 * @author Josh Cummings
 * @since 5.5
 */
public final class AuthorizationManagerAfterMethodInterceptor implements AuthorizationMethodInterceptor {

	private final Pointcut pointcut;

	private final AfterMethodAuthorizationManager<MethodInvocation> authorizationManager;

	/**
	 * Creates an instance.
	 * @param pointcut the {@link Pointcut} to use
	 * @param authorizationManager the {@link AuthorizationManager} to use
	 */
	public AuthorizationManagerAfterMethodInterceptor(Pointcut pointcut,
			AfterMethodAuthorizationManager<MethodInvocation> authorizationManager) {
		Assert.notNull(pointcut, "pointcut cannot be null");
		Assert.notNull(authorizationManager, "authorizationManager cannot be null");
		this.pointcut = pointcut;
		this.authorizationManager = authorizationManager;
	}

	/**
	 * Determine if an {@link Authentication} has access to the {@link MethodInvocation}
	 * using the {@link AuthorizationManager}.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param mi the {@link MethodInvocation} to check
	 * @throws AccessDeniedException if access is not granted
	 */
	@Override
	public Object invoke(Supplier<Authentication> authentication, MethodInvocation mi) throws Throwable {
		Object result = mi.proceed();
		this.authorizationManager.verify(authentication, mi, result);
		return result;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Pointcut getPointcut() {
		return this.pointcut;
	}

}
