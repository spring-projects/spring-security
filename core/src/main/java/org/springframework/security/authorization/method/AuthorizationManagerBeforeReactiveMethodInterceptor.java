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

import kotlinx.coroutines.reactive.ReactiveFlowKt;
import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.aop.Pointcut;
import org.springframework.core.KotlinDetector;
import org.springframework.core.MethodParameter;
import org.springframework.core.ReactiveAdapter;
import org.springframework.core.ReactiveAdapterRegistry;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * A {@link MethodInterceptor} which can determine if an {@link Authentication} has access
 * to the {@link MethodInvocation} using the configured
 * {@link ReactiveAuthorizationManager}.
 *
 * @author Evgeniy Cheban
 * @author Josh Cummings
 * @since 5.8
 */
public final class AuthorizationManagerBeforeReactiveMethodInterceptor implements AuthorizationAdvisor {

	private static final String COROUTINES_FLOW_CLASS_NAME = "kotlinx.coroutines.flow.Flow";

	private static final int RETURN_TYPE_METHOD_PARAMETER_INDEX = -1;

	private final Pointcut pointcut;

	private final ReactiveAuthorizationManager<MethodInvocation> authorizationManager;

	private int order = AuthorizationInterceptorsOrder.FIRST.getOrder();

	private final MethodAuthorizationDeniedHandler defaultHandler = new ThrowingMethodAuthorizationDeniedHandler();

	/**
	 * Creates an instance for the {@link PreAuthorize} annotation.
	 * @return the {@link AuthorizationManagerBeforeReactiveMethodInterceptor} to use
	 */
	public static AuthorizationManagerBeforeReactiveMethodInterceptor preAuthorize() {
		return preAuthorize(new PreAuthorizeReactiveAuthorizationManager());
	}

	/**
	 * Creates an instance for the {@link PreAuthorize} annotation.
	 * @param authorizationManager the {@link ReactiveAuthorizationManager} to use
	 * @return the {@link AuthorizationManagerBeforeReactiveMethodInterceptor} to use
	 */
	public static AuthorizationManagerBeforeReactiveMethodInterceptor preAuthorize(
			ReactiveAuthorizationManager<MethodInvocation> authorizationManager) {
		AuthorizationManagerBeforeReactiveMethodInterceptor interceptor = new AuthorizationManagerBeforeReactiveMethodInterceptor(
				AuthorizationMethodPointcuts.forAnnotations(PreAuthorize.class), authorizationManager);
		interceptor.setOrder(AuthorizationInterceptorsOrder.PRE_AUTHORIZE.getOrder());
		return interceptor;
	}

	/**
	 * Creates an instance.
	 * @param pointcut the {@link Pointcut} to use
	 * @param authorizationManager the {@link ReactiveAuthorizationManager} to use
	 */
	public AuthorizationManagerBeforeReactiveMethodInterceptor(Pointcut pointcut,
			ReactiveAuthorizationManager<MethodInvocation> authorizationManager) {
		Assert.notNull(pointcut, "pointcut cannot be null");
		Assert.notNull(authorizationManager, "authorizationManager cannot be null");
		this.pointcut = pointcut;
		this.authorizationManager = authorizationManager;
	}

	/**
	 * Determines if an {@link Authentication} has access to the {@link MethodInvocation}
	 * using the configured {@link ReactiveAuthorizationManager}.
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
		ReactiveAdapter adapter = ReactiveAdapterRegistry.getSharedInstance().getAdapter(type);
		if (hasFlowReturnType) {
			if (isSuspendingFunction) {
				return preAuthorized(mi, Flux.defer(() -> ReactiveMethodInvocationUtils.proceed(mi)));
			}
			else {
				Assert.state(adapter != null, () -> "The returnType " + type + " on " + method
						+ " must have a org.springframework.core.ReactiveAdapter registered");
				Flux<Object> response = preAuthorized(mi,
						Flux.defer(() -> adapter.toPublisher(ReactiveMethodInvocationUtils.proceed(mi))));
				return KotlinDelegate.asFlow(response);
			}
		}
		if (isMultiValue(type, adapter)) {
			Flux<?> result = preAuthorized(mi, Flux.defer(() -> ReactiveMethodInvocationUtils.proceed(mi)));
			return (adapter != null) ? adapter.fromPublisher(result) : result;
		}
		Mono<?> result = preAuthorized(mi, Mono.defer(() -> ReactiveMethodInvocationUtils.proceed(mi)));
		return (adapter != null) ? adapter.fromPublisher(result) : result;
	}

	private Flux<Object> preAuthorized(MethodInvocation mi, Flux<Object> mapping) {
		Mono<Authentication> authentication = ReactiveAuthenticationUtils.getAuthentication();
		return this.authorizationManager.authorize(authentication, mi)
			.switchIfEmpty(Mono.just(new AuthorizationDecision(false)))
			.flatMapMany((decision) -> {
				if (decision.isGranted()) {
					return mapping.onErrorResume(AuthorizationDeniedException.class,
							(deniedEx) -> postProcess(deniedEx, mi));
				}
				return postProcess(decision, mi);
			});
	}

	private Mono<Object> preAuthorized(MethodInvocation mi, Mono<Object> mapping) {
		Mono<Authentication> authentication = ReactiveAuthenticationUtils.getAuthentication();
		return this.authorizationManager.authorize(authentication, mi)
			.switchIfEmpty(Mono.just(new AuthorizationDecision(false)))
			.flatMap((decision) -> {
				if (decision.isGranted()) {
					return mapping.onErrorResume(AuthorizationDeniedException.class,
							(deniedEx) -> postProcess(deniedEx, mi));
				}
				return postProcess(decision, mi);
			});
	}

	private Mono<Object> postProcess(AuthorizationResult decision, MethodInvocation mi) {
		return Mono.fromSupplier(() -> {
			if (this.authorizationManager instanceof MethodAuthorizationDeniedHandler handler) {
				return handler.handleDeniedInvocation(mi, decision);
			}
			return this.defaultHandler.handleDeniedInvocation(mi, decision);
		}).flatMap((result) -> {
			if (Mono.class.isAssignableFrom(result.getClass())) {
				return (Mono<?>) result;
			}
			return Mono.justOrEmpty(result);
		});
	}

	private boolean isMultiValue(Class<?> returnType, ReactiveAdapter adapter) {
		if (Flux.class.isAssignableFrom(returnType)) {
			return true;
		}
		return adapter != null && adapter.isMultiValue();
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
