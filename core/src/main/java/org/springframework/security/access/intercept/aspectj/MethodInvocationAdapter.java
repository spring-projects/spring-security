/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.access.intercept.aspectj;

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Method;

import org.aopalliance.intercept.MethodInvocation;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.reflect.CodeSignature;

/**
 * Decorates a JoinPoint to allow it to be used with method-security infrastructure
 * classes which support {@code MethodInvocation} instances.
 *
 * @author Luke Taylor
 * @since 3.0.3
 */
public final class MethodInvocationAdapter implements MethodInvocation {

	private final ProceedingJoinPoint jp;

	private final Method method;

	private final Object target;

	MethodInvocationAdapter(JoinPoint jp) {
		this.jp = (ProceedingJoinPoint) jp;
		if (jp.getTarget() != null) {
			target = jp.getTarget();
		}
		else {
			// SEC-1295: target may be null if an ITD is in use
			target = jp.getSignature().getDeclaringType();
		}
		String targetMethodName = jp.getStaticPart().getSignature().getName();
		Class<?>[] types = ((CodeSignature) jp.getStaticPart().getSignature()).getParameterTypes();
		Class<?> declaringType = jp.getStaticPart().getSignature().getDeclaringType();

		method = findMethod(targetMethodName, declaringType, types);

		if (method == null) {
			throw new IllegalArgumentException("Could not obtain target method from JoinPoint: '" + jp + "'");
		}
	}

	private Method findMethod(String name, Class<?> declaringType, Class<?>[] params) {
		Method method = null;

		try {
			method = declaringType.getMethod(name, params);
		}
		catch (NoSuchMethodException ignored) {
		}

		if (method == null) {
			try {
				method = declaringType.getDeclaredMethod(name, params);
			}
			catch (NoSuchMethodException ignored) {
			}
		}

		return method;
	}

	public Method getMethod() {
		return method;
	}

	public Object[] getArguments() {
		return jp.getArgs();
	}

	public AccessibleObject getStaticPart() {
		return method;
	}

	public Object getThis() {
		return target;
	}

	public Object proceed() throws Throwable {
		return jp.proceed();
	}

}
