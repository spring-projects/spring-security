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

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;

import org.springframework.aop.support.AopUtils;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Provides security interception of AOP Alliance based method invocations.
 *
 * @author Evgeniy Cheban
 * @since 5.5
 */
public final class AuthorizationMethodInterceptor implements MethodInterceptor {

	private final AuthorizationMethodBeforeAdvice<MethodAuthorizationContext> beforeAdvice;

	private final AuthorizationMethodAfterAdvice<MethodAuthorizationContext> afterAdvice;

	/**
	 * Creates an instance.
	 * @param beforeAdvice the {@link AuthorizationMethodBeforeAdvice} to use
	 * @param afterAdvice the {@link AuthorizationMethodAfterAdvice} to use
	 */
	public AuthorizationMethodInterceptor(AuthorizationMethodBeforeAdvice<MethodAuthorizationContext> beforeAdvice,
			AuthorizationMethodAfterAdvice<MethodAuthorizationContext> afterAdvice) {
		this.beforeAdvice = beforeAdvice;
		this.afterAdvice = afterAdvice;
	}

	/**
	 * This method should be used to enforce security on a {@link MethodInvocation}.
	 * @param mi the method being invoked which requires a security decision
	 * @return the returned value from the {@link MethodInvocation}
	 */
	@Override
	public Object invoke(@NonNull MethodInvocation mi) throws Throwable {
		MethodAuthorizationContext methodAuthorizationContext = getMethodAuthorizationContext(mi);
		this.beforeAdvice.before(this::getAuthentication, methodAuthorizationContext);
		Object returnedObject = mi.proceed();
		return this.afterAdvice.after(this::getAuthentication, methodAuthorizationContext, returnedObject);
	}

	private MethodAuthorizationContext getMethodAuthorizationContext(MethodInvocation mi) {
		Object target = mi.getThis();
		Class<?> targetClass = (target != null) ? AopUtils.getTargetClass(target) : null;
		return new MethodAuthorizationContext(mi, targetClass);
	}

	private Authentication getAuthentication() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null) {
			throw new AuthenticationCredentialsNotFoundException(
					"An Authentication object was not found in the SecurityContext");
		}
		return authentication;
	}

}
