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
import org.aopalliance.intercept.MethodInvocation;

import org.springframework.aop.AfterAdvice;
import org.springframework.aop.PointcutAdvisor;
import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.security.core.Authentication;

/**
 * An {@link Advice} which can determine if an {@link Authentication} has access to the
 * returned object from the {@link MethodInvocation}. {@link #getPointcut()} describes
 * when the advice applies for the method.
 *
 * @param <T> the type of object that the authorization check is being done one.
 * @author Evgeniy Cheban
 * @author Josh Cummings
 * @since 5.5
 */
public interface AuthorizationMethodAfterAdvice<T> extends AfterAdvice, PointcutAdvisor, AopInfrastructureBean {

	/**
	 * {@inheritDoc}
	 */
	@Override
	default boolean isPerInstance() {
		return true;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	default Advice getAdvice() {
		return this;
	}

	/**
	 * Determine if an {@link Authentication} has access to a method invocation's return
	 * object.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param object the {@link T} object to check
	 * @param returnedObject the returned object from the method invocation to check
	 * @return the {@code Object} that will ultimately be returned to the caller (if an
	 * implementation does not wish to modify the object to be returned to the caller, the
	 * implementation should simply return the same object it was passed by the
	 * {@code returnedObject} method argument)
	 */
	Object after(Supplier<Authentication> authentication, T object, Object returnedObject);

}
