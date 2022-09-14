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
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.aop.Pointcut;
import org.springframework.aop.PointcutAdvisor;
import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.core.Ordered;
import org.springframework.core.ReactiveAdapter;
import org.springframework.core.ReactiveAdapterRegistry;
import org.springframework.security.access.prepost.PreAuthorize;
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
public final class AuthorizationManagerBeforeReactiveMethodInterceptor
		implements Ordered, MethodInterceptor, PointcutAdvisor, AopInfrastructureBean {

	private final Pointcut pointcut;

	private final ReactiveAuthorizationManager<MethodInvocation> authorizationManager;

	private int order = AuthorizationInterceptorsOrder.FIRST.getOrder();

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
		Assert.state(Publisher.class.isAssignableFrom(type),
				() -> String.format("The returnType %s on %s must return an instance of org.reactivestreams.Publisher "
						+ "(for example, a Mono or Flux) in order to support Reactor Context", type, method));
		Mono<Authentication> authentication = ReactiveAuthenticationUtils.getAuthentication();
		ReactiveAdapter adapter = ReactiveAdapterRegistry.getSharedInstance().getAdapter(type);
		Mono<Void> preAuthorize = this.authorizationManager.verify(authentication, mi);
		if (isMultiValue(type, adapter)) {
			Publisher<?> publisher = Flux.defer(() -> ReactiveMethodInvocationUtils.proceed(mi));
			Flux<?> result = preAuthorize.thenMany(publisher);
			return (adapter != null) ? adapter.fromPublisher(result) : result;
		}
		Mono<?> publisher = Mono.defer(() -> ReactiveMethodInvocationUtils.proceed(mi));
		Mono<?> result = preAuthorize.then(publisher);
		return (adapter != null) ? adapter.fromPublisher(result) : result;
	}

	private boolean isMultiValue(Class<?> returnType, ReactiveAdapter adapter) {
		if (Flux.class.isAssignableFrom(returnType)) {
			return true;
		}
		return adapter == null || adapter.isMultiValue();
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
