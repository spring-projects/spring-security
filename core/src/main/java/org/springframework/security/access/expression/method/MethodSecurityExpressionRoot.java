/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.access.expression.method;

import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;
import org.jspecify.annotations.Nullable;

import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.core.Authentication;

/**
 * Extended expression root object which contains extra method-specific functionality.
 *
 * @author Luke Taylor
 * @author Evgeniy Cheban
 * @author Steve Riesenberg
 * @since 3.0
 */
class MethodSecurityExpressionRoot extends SecurityExpressionRoot<MethodInvocation>
		implements MethodSecurityExpressionOperations {

	private @Nullable Object filterObject;

	private @Nullable Object returnObject;

	private @Nullable Object target;

	MethodSecurityExpressionRoot(Supplier<? extends @Nullable Authentication> authentication,
			MethodInvocation methodInvocation) {
		super(authentication, methodInvocation);
	}

	@Override
	public void setFilterObject(Object filterObject) {
		this.filterObject = filterObject;
	}

	@Override
	public @Nullable Object getFilterObject() {
		return this.filterObject;
	}

	@Override
	public void setReturnObject(@Nullable Object returnObject) {
		this.returnObject = returnObject;
	}

	@Override
	public @Nullable Object getReturnObject() {
		return this.returnObject;
	}

	/**
	 * Sets the "this" property for use in expressions. Typically this will be the "this"
	 * property of the {@code JoinPoint} representing the method invocation which is being
	 * protected.
	 * @param target the target object on which the method in is being invoked.
	 */
	void setThis(@Nullable Object target) {
		this.target = target;
	}

	@Override
	public @Nullable Object getThis() {
		return this.target;
	}

}
