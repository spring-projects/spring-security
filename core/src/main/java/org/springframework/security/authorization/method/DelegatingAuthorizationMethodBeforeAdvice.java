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

import java.lang.reflect.Method;
import java.util.List;
import java.util.function.Supplier;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.aop.MethodMatcher;
import org.springframework.aop.support.StaticMethodMatcher;
import org.springframework.core.log.LogMessage;
import org.springframework.security.core.Authentication;

/**
 * An {@link AuthorizationMethodBeforeAdvice} which delegates to a specific
 * {@link AuthorizationMethodBeforeAdvice} and grants access if all
 * {@link AuthorizationMethodBeforeAdvice}s granted or abstained. Denies access only if
 * one of the {@link AuthorizationMethodBeforeAdvice}s denied.
 *
 * @author Evgeniy Cheban
 * @since 5.5
 */
public final class DelegatingAuthorizationMethodBeforeAdvice
		implements AuthorizationMethodBeforeAdvice<MethodAuthorizationContext> {

	private final Log logger = LogFactory.getLog(getClass());

	private final MethodMatcher methodMatcher = new StaticMethodMatcher() {
		@Override
		public boolean matches(Method method, Class<?> targetClass) {
			for (AuthorizationMethodBeforeAdvice<MethodAuthorizationContext> delegate : DelegatingAuthorizationMethodBeforeAdvice.this.delegates) {
				MethodMatcher methodMatcher = delegate.getMethodMatcher();
				if (methodMatcher.matches(method, targetClass)) {
					return true;
				}
			}
			return false;
		}
	};

	private final List<AuthorizationMethodBeforeAdvice<MethodAuthorizationContext>> delegates;

	/**
	 * Creates an instance.
	 * @param delegates the {@link AuthorizationMethodBeforeAdvice}s to use
	 */
	public DelegatingAuthorizationMethodBeforeAdvice(
			List<AuthorizationMethodBeforeAdvice<MethodAuthorizationContext>> delegates) {
		this.delegates = delegates;
	}

	@Override
	public MethodMatcher getMethodMatcher() {
		return this.methodMatcher;
	}

	/**
	 * Delegates to a specific {@link AuthorizationMethodBeforeAdvice} and grants access
	 * if all {@link AuthorizationMethodBeforeAdvice}s granted or abstained. Denies only
	 * if one of the {@link AuthorizationMethodBeforeAdvice}s denied.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param methodAuthorizationContext the {@link MethodAuthorizationContext} to check
	 */
	@Override
	public void before(Supplier<Authentication> authentication, MethodAuthorizationContext methodAuthorizationContext) {
		if (this.logger.isTraceEnabled()) {
			this.logger.trace(LogMessage.format("Pre Authorizing %s", methodAuthorizationContext));
		}
		for (AuthorizationMethodBeforeAdvice<MethodAuthorizationContext> delegate : this.delegates) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Checking authorization on %s using %s", methodAuthorizationContext,
						delegate));
			}
			delegate.before(authentication, methodAuthorizationContext);
		}
	}

}
