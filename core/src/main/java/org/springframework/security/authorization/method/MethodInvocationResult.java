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

import org.springframework.util.Assert;

/**
 * A context object that contains a {@link MethodInvocation} and the result of that
 * {@link MethodInvocation}.
 *
 * @author Josh Cummings
 * @since 5.6
 */
public class MethodInvocationResult {

	private final MethodInvocation methodInvocation;

	private final Object result;

	/**
	 * Construct a {@link MethodInvocationResult} with the provided parameters
	 * @param methodInvocation the already-invoked {@link MethodInvocation}
	 * @param result the value returned from the {@link MethodInvocation}
	 */
	public MethodInvocationResult(MethodInvocation methodInvocation, Object result) {
		Assert.notNull(methodInvocation, "methodInvocation cannot be null");
		this.methodInvocation = methodInvocation;
		this.result = result;
	}

	/**
	 * Return the already-invoked {@link MethodInvocation}
	 * @return the already-invoked {@link MethodInvocation}
	 */
	public MethodInvocation getMethodInvocation() {
		return this.methodInvocation;
	}

	/**
	 * Return the result of the already-invoked {@link MethodInvocation}
	 * @return the result
	 */
	public Object getResult() {
		return this.result;
	}

}
