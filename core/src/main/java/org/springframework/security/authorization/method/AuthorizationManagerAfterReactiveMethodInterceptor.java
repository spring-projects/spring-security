/*
 * Copyright 2002-2024 the original author or authors.
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
import java.util.function.Function;

import kotlinx.coroutines.reactive.ReactiveFlowKt;
import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Signal;

import org.springframework.aop.Pointcut;
import org.springframework.core.KotlinDetector;
import org.springframework.core.MethodParameter;
import org.springframework.core.ReactiveAdapter;
import org.springframework.core.ReactiveAdapterRegistry;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * A {@link MethodInterceptor} which can determine if an {@link Authentication} has access
 * to the returned object from the {@link MethodInvocation} using the configured
 * {@link ReactiveAuthorizationManager}.
 *
 * @author Evgeniy Cheban
 * @since 5.8
 */
public final class AuthorizationManagerAfterReactiveMethodInterceptor implements AuthorizationAdvisor {

	private static final String COROUTINES_FLOW_CLASS_NAME = "kotlinx.coroutines.flow.Flow";

	private static final int RETURN_TYPE_METHOD_PARAMETER_INDEX = -1;

	private final Pointcut pointcut;

	private final ReactiveAuthorizationManager<MethodInvocationResult> authorizationManager;

	private int order = AuthorizationInterceptorsOrder.LAST.getOrder();

	private final MethodAuthorizationDeniedHandler defaultHandler = new ThrowingMethodAuthorizationDeniedHandler();

	/**
	 * Creates an instance for the {@link PostAuthorize} annotation.
	 * @return the {@link AuthorizationManagerAfterReactiveMethodInterceptor} to use
	 */
	public static AuthorizationManagerAfterReactiveMethodInterceptor postAuthorize() {
		return postAuthorize(new PostAuthorizeReactiveAuthorizationManager());
	}

	/**
	 * Creates an instance for the {@link PostAuthorize} annotation.
	 * @param authorizationManager the {@link ReactiveAuthorizationManager} to use
	 * @return the {@link AuthorizationManagerAfterReactiveMethodInterceptor} to use
	 */
	public static AuthorizationManagerAfterReactiveMethodInterceptor postAuthorize(
			ReactiveAuthorizationManager<MethodInvocationResult> authorizationManager) {
		AuthorizationManagerAfterReactiveMethodInterceptor interceptor = new AuthorizationManagerAfterReactiveMethodInterceptor(
				AuthorizationMethodPointcuts.forAnnotations(PostAuthorize.class), authorizationManager);
		interceptor.setOrder(AuthorizationInterceptorsOrder.POST_AUTHORIZE.getOrder());
		return interceptor;
	}

	/**
	 * Creates an instance.
	 * @param pointcut the {@link Pointcut} to use
	 * @param authorizationManager the {@link ReactiveAuthorizationManager} to use
	 */
	public AuthorizationManagerAfterReactiveMethodInterceptor(Pointcut pointcut,
			ReactiveAuthorizationManager<MethodInvocationResult> authorizationManager) {
		Assert.notNull(pointcut, "pointcut cannot be null");
		Assert.notNull(authorizationManager, "authorizationManager cannot be null");
		this.pointcut = pointcut;
		this.authorizationManager = authorizationManager;
	}

	/**
	 * Determines if an {@link Authentication} has access to the returned object from the
	 * {@link MethodInvocation} using the configured {@link ReactiveAuthorizationManager}.
	 * @param mi the {@link MethodInvocation} to use
	 * @return the {@link Publisher} from the {@link MethodInvocation} or a
	 * {@link Publisher} error if access is denied
	 */
	@Override
	public Object invoke(MethodInvocation mi) throws Throwable {
		Method method = mi.getMethod();
		Class<?> type = method.getReturnType();
		boolean isSuspendingFunction = KotlinDetector.isSuspendingFunction(method);
		boolean hasFlowReturnType = COROUTINES_FLOW_CLASS_NAME
			.equals(new MethodParameter(method, RETURN_TYPE_METHOD_PARAMETER_INDEX).getParameterType().getName());
		boolean hasReactiveReturnType = Publisher.class.isAssignableFrom(type) || isSuspendingFunction
				|| hasFlowReturnType;
		Assert.state(hasReactiveReturnType,
				() -> "The returnType " + type + " on " + method
						+ " must return an instance of org.reactivestreams.Publisher "
						+ "(for example, a Mono or Flux) or the function must be a Kotlin coroutine "
						+ "in order to support Reactor Context");
		Mono<Authentication> authentication = ReactiveAuthenticationUtils.getAuthentication();
		Function<Signal<?>, Mono<?>> postAuthorize = (signal) -> {
			if (signal.isOnComplete()) {
				return Mono.empty();
			}
			if (!signal.hasError()) {
				return postAuthorize(authentication, mi, signal.get());
			}
			if (signal.getThrowable() instanceof AuthorizationDeniedException denied) {
				return postProcess(denied, mi);
			}
			return Mono.error(signal.getThrowable());
		};
		ReactiveAdapter adapter = ReactiveAdapterRegistry.getSharedInstance().getAdapter(type);
		if (hasFlowReturnType) {
			if (isSuspendingFunction) {
				Publisher<?> publisher = ReactiveMethodInvocationUtils.proceed(mi);
				return Flux.from(publisher).materialize().flatMap(postAuthorize);
			}
			else {
				Assert.state(adapter != null, () -> "The returnType " + type + " on " + method
						+ " must have a org.springframework.core.ReactiveAdapter registered");
				Flux<?> response = Flux.defer(() -> adapter.toPublisher(ReactiveMethodInvocationUtils.proceed(mi)))
					.materialize()
					.flatMap(postAuthorize);
				return KotlinDelegate.asFlow(response);
			}
		}
		Publisher<?> publisher = ReactiveMethodInvocationUtils.proceed(mi);
		if (isMultiValue(type, adapter)) {
			Flux<?> flux = Flux.from(publisher).materialize().flatMap(postAuthorize);
			return (adapter != null) ? adapter.fromPublisher(flux) : flux;
		}
		Mono<?> mono = Mono.from(publisher).materialize().flatMap(postAuthorize);
		return (adapter != null) ? adapter.fromPublisher(mono) : mono;
	}

	private boolean isMultiValue(Class<?> returnType, ReactiveAdapter adapter) {
		if (Flux.class.isAssignableFrom(returnType)) {
			return true;
		}
		return adapter != null && adapter.isMultiValue();
	}

	private Mono<Object> postAuthorize(Mono<Authentication> authentication, MethodInvocation mi, Object result) {
		MethodInvocationResult invocationResult = new MethodInvocationResult(mi, result);
		return this.authorizationManager.authorize(authentication, invocationResult)
			.switchIfEmpty(Mono.just(new AuthorizationDecision(false)))
			.flatMap((decision) -> postProcess(decision, invocationResult));
	}

	private Mono<Object> postProcess(AuthorizationResult decision, MethodInvocationResult methodInvocationResult) {
		if (decision.isGranted()) {
			return Mono.just(methodInvocationResult.getResult());
		}
		return Mono.fromSupplier(() -> {
			if (this.authorizationManager instanceof MethodAuthorizationDeniedHandler handler) {
				return handler.handleDeniedInvocationResult(methodInvocationResult, decision);
			}
			return this.defaultHandler.handleDeniedInvocationResult(methodInvocationResult, decision);
		}).flatMap((processedResult) -> {
			if (Mono.class.isAssignableFrom(processedResult.getClass())) {
				return (Mono<?>) processedResult;
			}
			return Mono.justOrEmpty(processedResult);
		});
	}

	private Mono<Object> postProcess(AuthorizationResult decision, MethodInvocation methodInvocation) {
		return Mono.fromSupplier(() -> {
			if (this.authorizationManager instanceof MethodAuthorizationDeniedHandler handler) {
				return handler.handleDeniedInvocation(methodInvocation, decision);
			}
			return this.defaultHandler.handleDeniedInvocation(methodInvocation, decision);
		}).flatMap((processedResult) -> {
			if (Mono.class.isAssignableFrom(processedResult.getClass())) {
				return (Mono<?>) processedResult;
			}
			return Mono.justOrEmpty(processedResult);
		});
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

	/**
	 * Inner class to avoid a hard dependency on Kotlin at runtime.
	 */
	private static class KotlinDelegate {

		private static Object asFlow(Publisher<?> publisher) {
			return ReactiveFlowKt.asFlow(publisher);
		}

	}

}
