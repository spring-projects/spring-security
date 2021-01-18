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

package org.springframework.security.access.method;

import java.lang.reflect.Method;
import java.util.List;
import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.aop.MethodMatcher;
import org.springframework.aop.support.StaticMethodMatcher;
import org.springframework.core.log.LogMessage;
import org.springframework.security.core.Authentication;

/**
 * An {@link AuthorizationMethodAfterAdvice} which delegates to specific
 * {@link AuthorizationMethodAfterAdvice}s and returns the result (possibly modified) from
 * the {@link MethodInvocation}.
 *
 * @author Evgeniy Cheban
 * @since 5.5
 */
public final class DelegatingAuthorizationMethodAfterAdvice
		implements AuthorizationMethodAfterAdvice<MethodAuthorizationContext> {

	private final Log logger = LogFactory.getLog(getClass());

	private final MethodMatcher methodMatcher = new StaticMethodMatcher() {
		@Override
		public boolean matches(Method method, Class<?> targetClass) {
			for (AuthorizationMethodAfterAdvice<MethodAuthorizationContext> delegate : DelegatingAuthorizationMethodAfterAdvice.this.delegates) {
				MethodMatcher methodMatcher = delegate.getMethodMatcher();
				if (methodMatcher.matches(method, targetClass)) {
					return true;
				}
			}
			return false;
		}
	};

	private final List<AuthorizationMethodAfterAdvice<MethodAuthorizationContext>> delegates;

	/**
	 * Creates an instance.
	 * @param delegates the {@link AuthorizationMethodAfterAdvice}s to use
	 */
	public DelegatingAuthorizationMethodAfterAdvice(
			List<AuthorizationMethodAfterAdvice<MethodAuthorizationContext>> delegates) {
		this.delegates = delegates;
	}

	@Override
	public MethodMatcher getMethodMatcher() {
		return this.methodMatcher;
	}

	/**
	 * Delegates to specific {@link AuthorizationMethodAfterAdvice}s and returns the
	 * <code>returnedObject</code> (possibly modified) from the method argument.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param methodAuthorizationContext the {@link MethodAuthorizationContext} to check
	 * @param returnedObject the returned object from the {@link MethodInvocation} to
	 * check
	 * @return the <code>returnedObject</code> (possibly modified) from the method
	 * argument
	 */
	@Override
	public Object after(Supplier<Authentication> authentication, MethodAuthorizationContext methodAuthorizationContext,
			Object returnedObject) {
		if (this.logger.isTraceEnabled()) {
			this.logger.trace(
					LogMessage.format("Post Authorizing %s from %s", returnedObject, methodAuthorizationContext));
		}
		Object result = returnedObject;
		for (AuthorizationMethodAfterAdvice<MethodAuthorizationContext> delegate : this.delegates) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Checking authorization on %s from %s using %s", result,
						methodAuthorizationContext, delegate));
			}
			result = delegate.after(authentication, methodAuthorizationContext, result);
		}
		return result;
	}

}
