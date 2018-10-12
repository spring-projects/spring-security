/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.access.expression.method;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.IntStream;

import org.aopalliance.intercept.MethodInvocation;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.aop.framework.AopProxyUtils;
import org.springframework.aop.support.AopUtils;
import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.parameters.DefaultSecurityParameterNameDiscoverer;
import org.springframework.util.Assert;

/**
 * Internal security-specific EvaluationContext implementation which lazily adds the
 * method parameter values as variables (with the corresponding parameter names) if and
 * when they are required.
 *
 * @author Luke Taylor
 * @since 3.0
 */
class MethodSecurityEvaluationContext extends StandardEvaluationContext {
	private static final Log logger = LogFactory
			.getLog(MethodSecurityEvaluationContext.class);

	private ParameterNameDiscoverer parameterNameDiscoverer;
	private final MethodInvocation mi;
	private final AtomicBoolean argumentsAdded = new AtomicBoolean(false);

	/**
	 * Intended for testing. Don't use in practice as it creates a new parameter resolver
	 * for each instance. Use the constructor which takes the resolver, as an argument
	 * thus allowing for caching.
	 */
	public MethodSecurityEvaluationContext(Authentication user, MethodInvocation mi) {
		this(user, mi, new DefaultSecurityParameterNameDiscoverer());
	}

	public MethodSecurityEvaluationContext(Authentication user, MethodInvocation mi,
			ParameterNameDiscoverer parameterNameDiscoverer) {
		this.mi = mi;
		this.parameterNameDiscoverer = parameterNameDiscoverer;
	}

	@Override
	public Object lookupVariable(String name) {
		Object variable = super.lookupVariable(name);

		if (variable != null) {
			return variable;
		}

		if (this.argumentsAdded.compareAndSet(false, true)) {
			addArgumentsAsVariables();
		}

		return super.lookupVariable(name);
	}

	/**
	 * Gets the arguments from {@link MethodInvocation#getArguments()}, but substituting
	 * any variable references for actual arguments.
	 *
	 * @return The substituted arguments
	 * @since 5.1.2
	 */
	public Object[] getMethodInvocationArgs() {
		return getArgumentParameterNames().stream()
				.map(this::lookupVariable)
				.toArray(Object[]::new);
	}

	public void setParameterNameDiscoverer(ParameterNameDiscoverer parameterNameDiscoverer) {
		this.parameterNameDiscoverer = parameterNameDiscoverer;
	}

	private List<String> getArgumentParameterNames() {
		Object[] args = mi.getArguments();
		List<String> parameterNames = new ArrayList<>(args.length);

		if (args.length > 0) {
			Object targetObject = this.mi.getThis();
			// SEC-1454
			Class<?> targetClass = AopProxyUtils.ultimateTargetClass(targetObject);

			if (targetClass == null) {
				// TODO: Spring should do this, but there's a bug in ultimateTargetClass()
				// which returns null
				targetClass = targetObject.getClass();
			}

			Method method = AopUtils.getMostSpecificMethod(mi.getMethod(), targetClass);
			String[] paramNames = this.parameterNameDiscoverer.getParameterNames(method);

			if (paramNames == null) {
				logger.warn("Unable to resolve method parameter names for method: "
						+ method
						+ ". Debug symbol information is required if you are using parameter names in expressions.");
			}
			else {
				parameterNames.addAll(Arrays.asList(paramNames));
			}
		}

		return parameterNames;
	}

	private void addArgumentsAsVariables() {
		Object[] args = mi.getArguments();
		List<String> paramNames = getArgumentParameterNames();

		Assert.state(args.length == paramNames.size(),
				"Parameter names should have the same size as the argument list");

		IntStream.range(0, args.length)
				.forEach(i -> super.setVariable(paramNames.get(i), args[i]));
	}
}
