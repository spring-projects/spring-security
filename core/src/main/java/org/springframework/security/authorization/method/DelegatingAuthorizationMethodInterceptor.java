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

import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.aop.Pointcut;
import org.springframework.aop.support.ComposablePointcut;
import org.springframework.security.core.Authentication;

/**
 * Provides security interception of AOP Alliance based method invocations.
 *
 * Delegates to a collection of {@link AuthorizationMethodInterceptor}s
 *
 * @author Evgeniy Cheban
 * @author Josh Cummings
 * @since 5.5
 */
public final class DelegatingAuthorizationMethodInterceptor implements AuthorizationMethodInterceptor {

	private final List<AuthorizationMethodInterceptor> interceptors;

	private final Pointcut pointcut;

	/**
	 * Creates an instance using the provided parameters
	 * @param interceptors the delegate {@link AuthorizationMethodInterceptor}s to use
	 */
	public DelegatingAuthorizationMethodInterceptor(AuthorizationMethodInterceptor... interceptors) {
		this(Arrays.asList(interceptors));
	}

	/**
	 * Creates an instance using the provided parameters
	 * @param interceptors the delegate {@link AuthorizationMethodInterceptor}s to use
	 */
	public DelegatingAuthorizationMethodInterceptor(List<AuthorizationMethodInterceptor> interceptors) {
		ComposablePointcut pointcut = null;
		for (AuthorizationMethodInterceptor interceptor : interceptors) {
			if (pointcut == null) {
				pointcut = new ComposablePointcut(interceptor.getPointcut());
			}
			else {
				pointcut.union(interceptor.getPointcut());
			}
		}
		this.pointcut = pointcut;
		this.interceptors = interceptors;
	}

	/**
	 * Enforce security on this {@link MethodInvocation}.
	 * @param mi the method being invoked which requires a security decision
	 * @return the returned value from the {@link MethodInvocation}, possibly altered by
	 * the configured {@link AuthorizationMethodInterceptor}s
	 */
	@Override
	public Object invoke(Supplier<Authentication> authentication, MethodInvocation mi) throws Throwable {
		return new AuthorizationMethodInvocation(authentication, mi, this.interceptors).proceed();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Pointcut getPointcut() {
		return this.pointcut;
	}

}
