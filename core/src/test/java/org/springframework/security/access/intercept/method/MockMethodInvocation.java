/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.access.intercept.method;

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Method;

import org.aopalliance.intercept.MethodInvocation;

@SuppressWarnings("unchecked")
public class MockMethodInvocation implements MethodInvocation {

	private Method method;

	private Object targetObject;

	private Object[] arguments = new Object[0];

	public MockMethodInvocation(Object targetObject, Class clazz, String methodName, Class[] parameterTypes,
			Object[] arguments) throws NoSuchMethodException {
		this(targetObject, clazz, methodName, parameterTypes);
		this.arguments = arguments;
	}

	public MockMethodInvocation(Object targetObject, Class clazz, String methodName, Class... parameterTypes)
			throws NoSuchMethodException {
		this.method = clazz.getMethod(methodName, parameterTypes);
		this.targetObject = targetObject;
	}

	@Override
	public Object[] getArguments() {
		return this.arguments;
	}

	@Override
	public Method getMethod() {
		return this.method;
	}

	@Override
	public AccessibleObject getStaticPart() {
		return null;
	}

	@Override
	public Object getThis() {
		return this.targetObject;
	}

	@Override
	public Object proceed() {
		return null;
	}

}
