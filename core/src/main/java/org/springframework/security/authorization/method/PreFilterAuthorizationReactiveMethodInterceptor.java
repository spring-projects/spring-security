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
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.core.ReactiveAdapter;
import org.springframework.core.ReactiveAdapterRegistry;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.core.parameters.DefaultSecurityParameterNameDiscoverer;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * A {@link MethodInterceptor} which filters a reactive method argument by evaluating an
 * expression from the {@link PreFilter} annotation.
 *
 * @author Evgeniy Cheban
 * @since 5.8
 */
public final class PreFilterAuthorizationReactiveMethodInterceptor implements Ordered, MethodInterceptor,
		PointcutAdvisor, AopInfrastructureBean, BeanDefinitionRegistryPostProcessor {

	private final AuthorizationBeanFactoryPostProcessor beanFactoryPostProcessor = new AuthorizationBeanFactoryPostProcessor();

	private final PreFilterExpressionAttributeRegistry registry = new PreFilterExpressionAttributeRegistry();

	private final Pointcut pointcut = AuthorizationMethodPointcuts.forAnnotations(PreFilter.class);

	private ParameterNameDiscoverer parameterNameDiscoverer = new DefaultSecurityParameterNameDiscoverer();

	private int order = AuthorizationInterceptorsOrder.PRE_FILTER.getOrder();

	/**
	 * Sets the {@link MethodSecurityExpressionHandler}.
	 * @param expressionHandler the {@link MethodSecurityExpressionHandler} to use
	 */
	public void setExpressionHandler(MethodSecurityExpressionHandler expressionHandler) {
		this.registry.setExpressionHandler(expressionHandler);
	}

	/**
	 * Sets the {@link ParameterNameDiscoverer}.
	 * @param parameterNameDiscoverer the {@link ParameterNameDiscoverer} to use
	 */
	public void setParameterNameDiscoverer(ParameterNameDiscoverer parameterNameDiscoverer) {
		Assert.notNull(parameterNameDiscoverer, "parameterNameDiscoverer cannot be null");
		this.parameterNameDiscoverer = parameterNameDiscoverer;
	}

	/**
	 * Filters a reactive method argument by evaluating an expression from the
	 * {@link PreFilter} annotation.
	 * @param mi the {@link MethodInvocation} to use
	 * @return the {@link Publisher} to use
	 */
	@Override
	public Object invoke(MethodInvocation mi) throws Throwable {
		PreFilterExpressionAttributeRegistry.PreFilterExpressionAttribute attribute = this.registry.getAttribute(mi);
		if (attribute == PreFilterExpressionAttributeRegistry.PreFilterExpressionAttribute.NULL_ATTRIBUTE) {
			return ReactiveMethodInvocationUtils.<Publisher<?>>proceed(mi);
		}
		FilterTarget filterTarget = findFilterTarget(attribute.getFilterTarget(), mi);
		Mono<EvaluationContext> toInvoke = ReactiveAuthenticationUtils.getAuthentication()
				.map((auth) -> this.registry.getExpressionHandler().createEvaluationContext(auth, mi));
		if (filterTarget.value instanceof Mono<?>) {
			mi.getArguments()[filterTarget.index] = toInvoke
					.flatMap((ctx) -> filterMono((Mono<?>) filterTarget.value, attribute.getExpression(), ctx));
		}
		else {
			Flux<?> result = toInvoke
					.flatMapMany((ctx) -> filterPublisher(filterTarget.value, attribute.getExpression(), ctx));
			ReactiveAdapter adapter = ReactiveAdapterRegistry.getSharedInstance()
					.getAdapter(filterTarget.value.getClass());
			mi.getArguments()[filterTarget.index] = (adapter != null) ? adapter.fromPublisher(result) : result;
		}
		return ReactiveMethodInvocationUtils.<Publisher<?>>proceed(mi);
	}

	private FilterTarget findFilterTarget(String name, MethodInvocation mi) {
		Object value = null;
		int index = 0;
		if (StringUtils.hasText(name)) {
			Object target = mi.getThis();
			Class<?> targetClass = (target != null) ? AopUtils.getTargetClass(target) : null;
			Method specificMethod = AopUtils.getMostSpecificMethod(mi.getMethod(), targetClass);
			String[] parameterNames = this.parameterNameDiscoverer.getParameterNames(specificMethod);
			if (parameterNames != null && parameterNames.length > 0) {
				Object[] arguments = mi.getArguments();
				for (index = 0; index < parameterNames.length; index++) {
					if (name.equals(parameterNames[index])) {
						value = arguments[index];
						break;
					}
				}
				Assert.notNull(value,
						"Filter target was null, or no argument with name '" + name + "' found in method.");
			}
		}
		else {
			Object[] arguments = mi.getArguments();
			Assert.state(arguments.length == 1,
					"Unable to determine the method argument for filtering. Specify the filter target.");
			value = arguments[0];
			Assert.notNull(value,
					"Filter target was null. Make sure you passing the correct value in the method argument.");
		}
		Assert.state(value instanceof Publisher<?>, "Filter target must be an instance of Publisher.");
		return new FilterTarget((Publisher<?>) value, index);
	}

	private Mono<?> filterMono(Mono<?> filterTarget, Expression filterExpression, EvaluationContext ctx) {
		MethodSecurityExpressionOperations rootObject = (MethodSecurityExpressionOperations) ctx.getRootObject()
				.getValue();
		return filterTarget.filterWhen((filterObject) -> {
			rootObject.setFilterObject(filterObject);
			return ReactiveExpressionUtils.evaluateAsBoolean(filterExpression, ctx);
		});
	}

	private Flux<?> filterPublisher(Publisher<?> filterTarget, Expression filterExpression, EvaluationContext ctx) {
		MethodSecurityExpressionOperations rootObject = (MethodSecurityExpressionOperations) ctx.getRootObject()
				.getValue();
		return Flux.from(filterTarget).filterWhen((filterObject) -> {
			rootObject.setFilterObject(filterObject);
			return ReactiveExpressionUtils.evaluateAsBoolean(filterExpression, ctx);
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

	@Override
	public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) {
		this.beanFactoryPostProcessor.postProcessBeanDefinitionRegistry(registry);
	}

	@Override
	public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) {
		this.beanFactoryPostProcessor.postProcessBeanFactory(beanFactory);
	}

	private static final class FilterTarget {

		private final Publisher<?> value;

		private final int index;

		private FilterTarget(Publisher<?> value, int index) {
			this.value = value;
			this.index = index;
		}

	}

}
