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

import org.springframework.aop.PointcutAdvisor;
import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * A {@link MethodInterceptor} which can determine if an {@link Authentication} has access
 * to the {@link MethodInvocation}. {@link #getPointcut()} describes when the interceptor
 * applies.
 *
 * @author Evgeniy Cheban
 * @author Josh Cummings
 * @since 5.5
 */
public interface AuthorizationMethodInterceptor extends MethodInterceptor, PointcutAdvisor, AopInfrastructureBean {

	/**
	 * {@inheritDoc}
	 */
	@Override
	default Advice getAdvice() {
		return this;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	default boolean isPerInstance() {
		return true;
	}

	/**
	 * Determine if an {@link Authentication} has access to the {@link MethodInvocation}
	 * @param mi the {@link MethodInvocation} to intercept and potentially invoke
	 * @return the result of the method invocation
	 * @throws Throwable if the interceptor or the target object throws an exception
	 */
	default Object invoke(MethodInvocation mi) throws Throwable {
		Supplier<Authentication> supplier = () -> {
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			if (authentication == null) {
				throw new AuthenticationCredentialsNotFoundException(
						"An Authentication object was not found in the SecurityContext");
			}
			return authentication;
		};
		return invoke(supplier, new AuthorizationMethodInvocation(supplier, mi));
	}

	/**
	 * Determine if an {@link Authentication} has access to the {@link MethodInvocation}
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param mi the {@link MethodInvocation} to intercept and potentially invoke
	 * @return the result of the method invocation
	 * @throws Throwable if the interceptor or the target object throws an exception
	 */
	Object invoke(Supplier<Authentication> authentication, MethodInvocation mi) throws Throwable;

}
