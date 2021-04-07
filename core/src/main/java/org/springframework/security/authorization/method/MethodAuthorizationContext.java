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

import org.aopalliance.intercept.MethodInvocation;

/**
 * An authorization context which is holds the {@link MethodInvocation}, the target class
 * and the returned object.
 *
 * @author Evgeniy Cheban
 * @since 5.5
 */
public final class MethodAuthorizationContext {

	private final MethodInvocation methodInvocation;

	private final Class<?> targetClass;

	private Object returnObject;

	/**
	 * Creates an instance.
	 * @param methodInvocation the {@link MethodInvocation} to use
	 * @param targetClass the target class to use
	 */
	public MethodAuthorizationContext(MethodInvocation methodInvocation, Class<?> targetClass) {
		this.methodInvocation = methodInvocation;
		this.targetClass = targetClass;
	}

	/**
	 * Returns the {@link MethodInvocation}.
	 * @return the {@link MethodInvocation} to use
	 */
	public MethodInvocation getMethodInvocation() {
		return this.methodInvocation;
	}

	/**
	 * Returns the target class.
	 * @return the target class to use
	 */
	public Class<?> getTargetClass() {
		return this.targetClass;
	}

	/**
	 * Returns the returned object from the {@link MethodInvocation}.
	 * @return the returned object from the {@link MethodInvocation} to use
	 */
	public Object getReturnObject() {
		return this.returnObject;
	}

	/**
	 * Sets the returned object from the {@link MethodInvocation}.
	 * @param returnObject the returned object from the {@link MethodInvocation} to use
	 */
	public void setReturnObject(Object returnObject) {
		this.returnObject = returnObject;
	}

	@Override
	public String toString() {
		return "MethodAuthorizationContext[methodInvocation=" + this.methodInvocation + ", targetClass="
				+ this.targetClass + ", returnObject=" + this.returnObject + ']';
	}

}
