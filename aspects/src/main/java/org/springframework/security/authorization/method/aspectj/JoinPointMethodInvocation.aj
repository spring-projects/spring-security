/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.authorization.method.aspectj;

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Method;
import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.reflect.CodeSignature;

import org.springframework.util.Assert;

class JoinPointMethodInvocation implements MethodInvocation {

	private final JoinPoint jp;

	private final Method method;

	private final Object target;

	private final Supplier<Object> proceed;

	JoinPointMethodInvocation(JoinPoint jp, Supplier<Object> proceed) {
		this.jp = jp;
		if (jp.getTarget() != null) {
			this.target = jp.getTarget();
		}
		else {
			// SEC-1295: target may be null if an ITD is in use
			this.target = jp.getSignature().getDeclaringType();
		}
		String targetMethodName = jp.getStaticPart().getSignature().getName();
		Class<?>[] types = ((CodeSignature) jp.getStaticPart().getSignature()).getParameterTypes();
		Class<?> declaringType = jp.getStaticPart().getSignature().getDeclaringType();
		this.method = findMethod(targetMethodName, declaringType, types);
		Assert.notNull(this.method, () -> "Could not obtain target method from JoinPoint: '" + jp + "'");
		this.proceed = proceed;
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

	@Override
	public Method getMethod() {
		return this.method;
	}

	@Override
	public Object[] getArguments() {
		return this.jp.getArgs();
	}

	@Override
	public AccessibleObject getStaticPart() {
		return this.method;
	}

	@Override
	public Object getThis() {
		return this.target;
	}

	@Override
	public Object proceed() throws Throwable {
		return this.proceed.get();
	}

}
