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
import java.util.HashSet;
import java.util.Set;

import org.aspectj.weaver.tools.PointcutExpression;
import org.aspectj.weaver.tools.PointcutParser;
import org.aspectj.weaver.tools.PointcutPrimitive;

import org.springframework.aop.ClassFilter;
import org.springframework.aop.MethodMatcher;
import org.springframework.aop.Pointcut;

class AspectJMethodMatcher implements MethodMatcher, ClassFilter, Pointcut {

	private static final PointcutParser parser;

	static {
		Set<PointcutPrimitive> supportedPrimitives = new HashSet<>(3);
		supportedPrimitives.add(PointcutPrimitive.EXECUTION);
		supportedPrimitives.add(PointcutPrimitive.ARGS);
		supportedPrimitives.add(PointcutPrimitive.REFERENCE);
		parser = PointcutParser.getPointcutParserSupportingSpecifiedPrimitivesAndUsingContextClassloaderForResolution(
				supportedPrimitives);
	}

	private final PointcutExpression expression;

	AspectJMethodMatcher(String expression) {
		this.expression = parser.parsePointcutExpression(expression);
	}

	@Override
	public boolean matches(Class<?> clazz) {
		return this.expression.couldMatchJoinPointsInType(clazz);
	}

	@Override
	public boolean matches(Method method, Class<?> targetClass) {
		return this.expression.matchesMethodExecution(method).alwaysMatches();
	}

	@Override
	public boolean isRuntime() {
		return false;
	}

	@Override
	public boolean matches(Method method, Class<?> targetClass, Object... args) {
		return matches(method, targetClass);
	}

	@Override
	public ClassFilter getClassFilter() {
		return this;
	}

	@Override
	public MethodMatcher getMethodMatcher() {
		return this;
	}

}
