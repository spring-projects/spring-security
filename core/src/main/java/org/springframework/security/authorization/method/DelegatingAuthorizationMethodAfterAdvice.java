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

import java.util.List;
import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.aop.Pointcut;
import org.springframework.aop.support.ComposablePointcut;
import org.springframework.core.log.LogMessage;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * An {@link AuthorizationMethodAfterAdvice} which delegates to specific
 * {@link AuthorizationMethodAfterAdvice}s and returns the result (possibly modified) from
 * the {@link MethodInvocation}.
 *
 * @author Evgeniy Cheban
 * @author Josh Cummings
 * @since 5.5
 */
public final class DelegatingAuthorizationMethodAfterAdvice<T> implements AuthorizationMethodAfterAdvice<T> {

	private final Log logger = LogFactory.getLog(getClass());

	private final Pointcut pointcut;

	private final List<AuthorizationMethodAfterAdvice<T>> delegates;

	/**
	 * Creates an instance.
	 * @param delegates the {@link AuthorizationMethodAfterAdvice}s to use
	 */
	public DelegatingAuthorizationMethodAfterAdvice(List<AuthorizationMethodAfterAdvice<T>> delegates) {
		Assert.notEmpty(delegates, "delegates cannot be empty");
		this.delegates = delegates;
		ComposablePointcut pointcut = null;
		for (AuthorizationMethodAfterAdvice<?> advice : delegates) {
			if (pointcut == null) {
				pointcut = new ComposablePointcut(advice.getPointcut());
			}
			else {
				pointcut.union(advice.getPointcut());
			}
		}
		this.pointcut = pointcut;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Pointcut getPointcut() {
		return this.pointcut;
	}

	/**
	 * Delegate to a series of {@link AuthorizationMethodAfterAdvice}s, each of which may
	 * replace the {@code returnedObject} with its own
	 *
	 * Advices may be of type {@link AuthorizationManagerMethodAfterAdvice} in which case,
	 * they will throw an
	 * {@link org.springframework.security.access.AccessDeniedException} in the event that
	 * they deny access to the {@code returnedObject}.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param object the {@link MethodAuthorizationContext} to check
	 * @param returnedObject the returned object from the original method invocation
	 * @throws org.springframework.security.access.AccessDeniedException if any delegate
	 * advices deny access
	 */
	@Override
	public Object after(Supplier<Authentication> authentication, T object, Object returnedObject) {
		if (this.logger.isTraceEnabled()) {
			this.logger.trace(LogMessage.format("Post Authorizing %s from %s", returnedObject, object));
		}
		Object result = returnedObject;
		for (AuthorizationMethodAfterAdvice<T> delegate : this.delegates) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(
						LogMessage.format("Checking authorization on %s from %s using %s", result, object, delegate));
			}
			result = delegate.after(authentication, object, result);
		}
		return result;
	}

}
