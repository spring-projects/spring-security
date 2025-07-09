/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.util;

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Method;

import org.aopalliance.intercept.MethodInvocation;
import org.jspecify.annotations.Nullable;

import org.springframework.util.Assert;

/**
 * Represents the AOP Alliance <code>MethodInvocation</code>.
 *
 * @author Ben Alex
 */
public class SimpleMethodInvocation implements MethodInvocation {

	private @Nullable Method method;

	private Object[] arguments;

	private @Nullable Object targetObject;

	// @formatter:off See https://github.com/spring-io/spring-javaformat/issues/
	public SimpleMethodInvocation(@Nullable Object targetObject, Method method, Object @Nullable... arguments) {
		this.targetObject = targetObject;
		this.method = method;
		this.arguments = (arguments != null) ? arguments : new Object[0];
	}
	// @formatter:on

	public SimpleMethodInvocation() {
		this.arguments = new Object[0];
	}

	@Override
	public Object[] getArguments() {
		return this.arguments;
	}

	@Override
	public Method getMethod() {
		Assert.state(this.method != null, "method cannot be null");
		return this.method;
	}

	@Override
	public AccessibleObject getStaticPart() {
		throw new UnsupportedOperationException("mock method not implemented");
	}

	@Override
	public @Nullable Object getThis() {
		return this.targetObject;
	}

	@Override
	public Object proceed() {
		throw new UnsupportedOperationException("mock method not implemented");
	}

	@Override
	public String toString() {
		return "method invocation [" + this.method + "]";
	}

}
