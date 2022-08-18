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
import org.springframework.expression.EvaluationContext;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.util.Assert;

/**
 * A {@link MethodInterceptor} which filters the returned object from the
 * {@link MethodInvocation} by evaluating an expression from the {@link PostFilter}
 * annotation.
 *
 * @author Evgeniy Cheban
 * @since 5.8
 */
public final class PostFilterAuthorizationReactiveMethodInterceptor
		implements Ordered, MethodInterceptor, PointcutAdvisor, AopInfrastructureBean {

	private final PostFilterExpressionAttributeRegistry registry;

	private final Pointcut pointcut = AuthorizationMethodPointcuts.forAnnotations(PostFilter.class);

	private int order = AuthorizationInterceptorsOrder.POST_FILTER.getOrder();

	/**
	 * Creates an instance.
	 */
	public PostFilterAuthorizationReactiveMethodInterceptor() {
		this(new DefaultMethodSecurityExpressionHandler());
	}

	/**
	 * Creates an instance.
	 */
	public PostFilterAuthorizationReactiveMethodInterceptor(MethodSecurityExpressionHandler expressionHandler) {
		Assert.notNull(expressionHandler, "expressionHandler cannot be null");
		this.registry = new PostFilterExpressionAttributeRegistry(expressionHandler);
	}

	/**
	 * Filters the returned object from the {@link MethodInvocation} by evaluating an
	 * expression from the {@link PostFilter} annotation.
	 * @param mi the {@link MethodInvocation} to use
	 * @return the {@link Publisher} to use
	 */
	@Override
	public Object invoke(MethodInvocation mi) throws Throwable {
		ExpressionAttribute attribute = this.registry.getAttribute(mi);
		if (attribute == ExpressionAttribute.NULL_ATTRIBUTE) {
			return ReactiveMethodInvocationUtils.proceed(mi);
		}
		Mono<EvaluationContext> toInvoke = ReactiveAuthenticationUtils.getAuthentication()
				.map((auth) -> this.registry.getExpressionHandler().createEvaluationContext(auth, mi));
		Method method = mi.getMethod();
		Class<?> type = method.getReturnType();
		Assert.state(Publisher.class.isAssignableFrom(type),
				() -> String.format("The parameter type %s on %s must be an instance of org.reactivestreams.Publisher "
						+ "(for example, a Mono or Flux) in order to support Reactor Context", type, method));
		ReactiveAdapter adapter = ReactiveAdapterRegistry.getSharedInstance().getAdapter(type);
		if (isMultiValue(type, adapter)) {
			Publisher<?> publisher = Flux.defer(() -> ReactiveMethodInvocationUtils.proceed(mi));
			Flux<?> flux = toInvoke.flatMapMany((ctx) -> filterMultiValue(publisher, ctx, attribute));
			return (adapter != null) ? adapter.fromPublisher(flux) : flux;
		}
		Publisher<?> publisher = Mono.defer(() -> ReactiveMethodInvocationUtils.proceed(mi));
		Mono<?> mono = toInvoke.flatMap((ctx) -> filterSingleValue(publisher, ctx, attribute));
		return (adapter != null) ? adapter.fromPublisher(mono) : mono;
	}

	private boolean isMultiValue(Class<?> returnType, ReactiveAdapter adapter) {
		if (Flux.class.isAssignableFrom(returnType)) {
			return true;
		}
		return adapter == null || adapter.isMultiValue();
	}

	private Mono<?> filterSingleValue(Publisher<?> publisher, EvaluationContext ctx, ExpressionAttribute attribute) {
		return Mono.from(publisher).doOnNext((result) -> setFilterObject(ctx, result))
				.flatMap((result) -> postFilter(ctx, result, attribute));
	}

	private Flux<?> filterMultiValue(Publisher<?> publisher, EvaluationContext ctx, ExpressionAttribute attribute) {
		return Flux.from(publisher).doOnNext((result) -> setFilterObject(ctx, result))
				.flatMap((result) -> postFilter(ctx, result, attribute));
	}

	private void setFilterObject(EvaluationContext ctx, Object result) {
		((MethodSecurityExpressionOperations) ctx.getRootObject().getValue()).setFilterObject(result);
	}

	private Mono<?> postFilter(EvaluationContext ctx, Object result, ExpressionAttribute attribute) {
		return ReactiveExpressionUtils.evaluateAsBoolean(attribute.getExpression(), ctx)
				.flatMap((granted) -> granted ? Mono.just(result) : Mono.empty());
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
