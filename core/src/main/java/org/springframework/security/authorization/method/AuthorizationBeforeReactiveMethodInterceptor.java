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

package org.springframework.security.authorization.method;

import java.lang.reflect.Method;

import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.reactivestreams.Publisher;

import org.springframework.aop.Pointcut;
import org.springframework.aop.PointcutAdvisor;
import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.core.Ordered;
import org.springframework.core.ReactiveAdapter;
import org.springframework.core.ReactiveAdapterRegistry;
import org.springframework.util.Assert;

/**
 * A {@link MethodInterceptor} which validates and transforms the return type for methods
 * that return a {@link Publisher}.
 *
 * @author Evgeniy Cheban
 * @since 5.8
 */
final class AuthorizationBeforeReactiveMethodInterceptor
		implements Ordered, MethodInterceptor, PointcutAdvisor, AopInfrastructureBean {

	private final Pointcut pointcut = AuthorizationMethodPointcuts.forAllAnnotations();

	private final int order = AuthorizationInterceptorsOrder.FIRST.getOrder();

	@Override
	public Object invoke(MethodInvocation mi) throws Throwable {
		Method method = mi.getMethod();
		Class<?> returnType = method.getReturnType();
		Assert.state(Publisher.class.isAssignableFrom(returnType),
				() -> "The returnType " + returnType + " on " + method
						+ " must return an instance of org.reactivestreams.Publisher "
						+ "(i.e. Mono / Flux) or the function must be a Kotlin coroutine "
						+ "function in order to support Reactor Context");
		Publisher<?> publisher = ReactiveMethodInvocationUtils.proceed(mi);
		ReactiveAdapter adapter = ReactiveAdapterRegistry.getSharedInstance().getAdapter(returnType);
		return (adapter != null) ? adapter.fromPublisher(publisher) : publisher;
	}

	@Override
	public Pointcut getPointcut() {
		return this.pointcut;
	}

	@Override
	public Advice getAdvice() {
		return this;
	}

	@Override
	public boolean isPerInstance() {
		return true;
	}

	@Override
	public int getOrder() {
		return this.order;
	}

}
