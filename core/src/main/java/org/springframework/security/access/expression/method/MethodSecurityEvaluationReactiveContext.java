/*
 * Copyright 2002-2020 the original author or authors.
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

import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.aop.framework.AopProxyUtils;
import org.springframework.aop.support.AopUtils;
import org.springframework.context.expression.MethodBasedEvaluationContext;
import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.parameters.DefaultSecurityParameterNameDiscoverer;
import reactor.core.publisher.Mono;

import java.lang.reflect.Method;


/**
 * Internal security-specific EvaluationContext implementation which lazily adds the
 * method parameter values as variables (with the corresponding parameter names) if and
 * when they are required.
 *
 * @author Luke Taylor
 * @author Daniel Bustamante
 * @author Sheiy
 * @since 5.4
 */
class MethodSecurityEvaluationReactiveContext extends MethodBasedEvaluationContext {
	private static final Log logger = LogFactory
			.getLog(MethodSecurityEvaluationReactiveContext.class);

	/**
	 * Intended for testing. Don't use in practice as it creates a new parameter resolver
	 * for each instance. Use the constructor which takes the resolver, as an argument
	 * thus allowing for caching.
	 */
	MethodSecurityEvaluationReactiveContext(Mono<Authentication> user, MethodInvocation mi) {
		this(user, mi, new DefaultSecurityParameterNameDiscoverer());
	}

	MethodSecurityEvaluationReactiveContext(Mono<Authentication> user, MethodInvocation mi,
			ParameterNameDiscoverer parameterNameDiscoverer) {
		super(mi.getThis(), getSpecificMethod(mi), mi.getArguments(), parameterNameDiscoverer);
	}

	private static Method getSpecificMethod(MethodInvocation mi) {
		return AopUtils.getMostSpecificMethod(mi.getMethod(), AopProxyUtils.ultimateTargetClass(mi.getThis()));
	}
}
