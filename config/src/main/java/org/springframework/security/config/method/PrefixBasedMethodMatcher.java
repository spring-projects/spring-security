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

package org.springframework.security.config.method;

import java.lang.reflect.Method;

import org.springframework.aop.ClassFilter;
import org.springframework.aop.MethodMatcher;
import org.springframework.aop.Pointcut;
import org.springframework.aop.support.RootClassFilter;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;

class PrefixBasedMethodMatcher implements MethodMatcher, Pointcut {

	private static final ClassLoader beanClassLoader = ClassUtils.getDefaultClassLoader();

	private final ClassFilter classFilter;

	private final String methodPrefix;

	PrefixBasedMethodMatcher(Class<?> javaType, String methodPrefix) {
		this.classFilter = new RootClassFilter(javaType);
		this.methodPrefix = methodPrefix;
	}

	static PrefixBasedMethodMatcher fromClass(String className, String method) {
		int lastDotIndex = method.lastIndexOf(".");
		Assert.isTrue(lastDotIndex != -1 || StringUtils.hasText(className),
				() -> "'" + method + "' is not a valid method name: format is FQN.methodName");
		if (lastDotIndex == -1) {
			Class<?> javaType = ClassUtils.resolveClassName(className, beanClassLoader);
			return new PrefixBasedMethodMatcher(javaType, method);
		}
		String methodName = method.substring(lastDotIndex + 1);
		Assert.hasText(methodName, () -> "Method not found for '" + method + "'");
		String typeName = method.substring(0, lastDotIndex);
		Class<?> javaType = ClassUtils.resolveClassName(typeName, beanClassLoader);
		return new PrefixBasedMethodMatcher(javaType, method);
	}

	@Override
	public ClassFilter getClassFilter() {
		return this.classFilter;
	}

	@Override
	public MethodMatcher getMethodMatcher() {
		return this;
	}

	@Override
	public boolean matches(Method method, Class<?> targetClass) {
		return matches(this.methodPrefix, method.getName());
	}

	@Override
	public boolean isRuntime() {
		return false;
	}

	@Override
	public boolean matches(Method method, Class<?> targetClass, Object... args) {
		return matches(this.methodPrefix, method.getName());
	}

	private boolean matches(String mappedName, String methodName) {
		boolean equals = methodName.equals(mappedName);
		return equals || prefixMatches(mappedName, methodName) || suffixMatches(mappedName, methodName);
	}

	private boolean prefixMatches(String mappedName, String methodName) {
		return mappedName.endsWith("*") && methodName.startsWith(mappedName.substring(0, mappedName.length() - 1));
	}

	private boolean suffixMatches(String mappedName, String methodName) {
		return mappedName.startsWith("*") && methodName.endsWith(mappedName.substring(1));
	}

}
