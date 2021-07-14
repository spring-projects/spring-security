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

import java.lang.reflect.Method;

import kotlin.coroutines.Continuation;
import kotlinx.coroutines.reactive.AwaitKt;
import kotlinx.coroutines.reactive.ReactiveFlowKt;
import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.reactivestreams.Publisher;
import reactor.core.Exceptions;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.aop.Pointcut;
import org.springframework.aop.PointcutAdvisor;
import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.core.CoroutinesUtils;
import org.springframework.core.KotlinDetector;
import org.springframework.core.MethodParameter;
import org.springframework.core.Ordered;
import org.springframework.core.ReactiveAdapter;
import org.springframework.core.ReactiveAdapterRegistry;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.util.Assert;

/**
 * A {@link MethodInterceptor} for methods that return {@link Mono} or {@link Flux} and
 * Kotlin coroutine functions. The {@link #before(Mono, MethodInvocation)} is used to
 * perform an authorization check before the {@link MethodInvocation}. The
 * {@link #after(Mono, MethodInvocationResult)} is used to perform an authorization check
 * after the {@link MethodInvocation}.
 *
 * @author Evgeniy Cheban
 */
public abstract class AbstractReactiveMethodInterceptor
		implements MethodInterceptor, PointcutAdvisor, Ordered, AopInfrastructureBean {

	private static final String COROUTINES_FLOW_CLASS_NAME = "kotlinx.coroutines.flow.Flow";

	private static final int RETURN_TYPE_METHOD_PARAMETER_INDEX = -1;

	private final Authentication anonymous = new AnonymousAuthenticationToken("key", "anonymous",
			AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

	private final Pointcut pointcut;

	private int order = AuthorizationInterceptorsOrder.FIRST.getOrder();

	/**
	 * Creates an instance.
	 * @param pointcut the {@link Pointcut} to use
	 */
	protected AbstractReactiveMethodInterceptor(Pointcut pointcut) {
		Assert.notNull(pointcut, "pointcut cannot be null");
		this.pointcut = pointcut;
	}

	@Override
	public final Object invoke(MethodInvocation mi) throws Throwable {
		Method method = mi.getMethod();
		Class<?> returnType = method.getReturnType();
		boolean isSuspendingFunction = KotlinDetector.isSuspendingFunction(method);
		boolean hasFlowReturnType = COROUTINES_FLOW_CLASS_NAME
				.equals(new MethodParameter(method, RETURN_TYPE_METHOD_PARAMETER_INDEX).getParameterType().getName());
		boolean hasReactiveReturnType = Publisher.class.isAssignableFrom(returnType) || isSuspendingFunction
				|| hasFlowReturnType;
		Assert.state(hasReactiveReturnType,
				() -> "The returnType " + returnType + " on " + method
						+ " must return an instance of org.reactivestreams.Publisher "
						+ "(i.e. Mono / Flux) or the function must be a Kotlin coroutine "
						+ "function in order to support Reactor Context");
		// @formatter:off
		Mono<Authentication> authentication = ReactiveSecurityContextHolder.getContext()
				.map(SecurityContext::getAuthentication)
				.defaultIfEmpty(this.anonymous);
		// @formatter:on
		Mono<?> toInvoke = before(authentication, mi);
		if (Mono.class.isAssignableFrom(returnType)) {
			return toInvoke.then(Mono.defer(() -> this.<Mono<?>>proceed(mi)))
					.flatMap((result) -> after(authentication, new MethodInvocationResult(mi, result)));
		}
		if (hasFlowReturnType) {
			Flux<?> response;
			if (isSuspendingFunction) {
				response = toInvoke
						.thenMany(Flux.defer(() -> CoroutinesUtils.invokeSuspendingFunction(mi.getMethod(),
								mi.getThis(), mi.getArguments())))
						.flatMap((result) -> after(authentication, new MethodInvocationResult(mi, result)));
			}
			else {
				ReactiveAdapter adapter = ReactiveAdapterRegistry.getSharedInstance().getAdapter(returnType);
				Assert.state(adapter != null, () -> "The returnType " + returnType + " on " + method
						+ " must have a org.springframework.core.ReactiveAdapter registered");
				response = toInvoke.thenMany(Flux.defer(() -> adapter.toPublisher(proceed(mi))))
						.flatMap((result) -> after(authentication, new MethodInvocationResult(mi, result)));
			}
			return ReactiveFlowKt.asFlow(response);
		}
		if (isSuspendingFunction) {
			Mono<?> response = toInvoke
					.then(Mono.defer(() -> Mono.from(
							CoroutinesUtils.invokeSuspendingFunction(mi.getMethod(), mi.getThis(), mi.getArguments()))))
					.flatMap((result) -> after(authentication, new MethodInvocationResult(mi, result)));
			return AwaitKt.awaitSingleOrNull(response,
					(Continuation<Object>) mi.getArguments()[mi.getArguments().length - 1]);
		}
		return toInvoke.thenMany(Flux.defer(() -> this.<Publisher<?>>proceed(mi)))
				.flatMap((result) -> after(authentication, new MethodInvocationResult(mi, result)));
	}

	/**
	 * Determines if an {@link Authentication} has access to the {@link MethodInvocation}.
	 * @param authentication the {@link Mono} of the {@link Authentication} to check
	 * @param mi the {@link MethodInvocation} to check
	 * @return an empty {@link Mono} if access is granted or a {@link Mono} error if
	 * access is denied
	 */
	protected Mono<?> before(Mono<Authentication> authentication, MethodInvocation mi) {
		return Mono.empty();
	}

	/**
	 * Determines if an {@link Authentication} has access to the result of the
	 * {@link MethodInvocation}.
	 * @param authentication the {@link Mono} of the {@link Authentication} to check
	 * @param result the {@link MethodInvocationResult} to check
	 * @return the {@link Mono} of the {@link MethodInvocationResult#getResult()} if
	 * access is granted or a {@link Mono} error if access is denied
	 */
	protected Mono<?> after(Mono<Authentication> authentication, MethodInvocationResult result) {
		return Mono.just(result.getResult());
	}

	@SuppressWarnings("unchecked")
	private <T> T proceed(MethodInvocation methodInvocation) {
		try {
			return (T) methodInvocation.proceed();
		}
		catch (Throwable throwable) {
			throw Exceptions.propagate(throwable);
		}
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

	public void setOrder(int order) {
		this.order = order;
	}

}
