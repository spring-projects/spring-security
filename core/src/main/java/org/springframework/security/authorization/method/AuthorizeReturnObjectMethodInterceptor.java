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
import java.util.function.Predicate;

import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInvocation;

import org.springframework.aop.Pointcut;
import org.springframework.aop.support.Pointcuts;
import org.springframework.aop.support.StaticMethodMatcherPointcut;
import org.springframework.security.authorization.AuthorizationProxyFactory;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;

/**
 * A method interceptor that applies the given {@link AuthorizationProxyFactory} to any
 * return value annotated with {@link AuthorizeReturnObject}
 *
 * @author Josh Cummings
 * @since 6.3
 * @see AuthorizationAdvisorProxyFactory
 */
public final class AuthorizeReturnObjectMethodInterceptor implements AuthorizationAdvisor {

	private final AuthorizationProxyFactory authorizationProxyFactory;

	private Pointcut pointcut = Pointcuts.intersection(
			new MethodReturnTypePointcut(Predicate.not(ClassUtils::isVoidType)),
			AuthorizationMethodPointcuts.forAnnotations(AuthorizeReturnObject.class));

	private int order = AuthorizationInterceptorsOrder.SECURE_RESULT.getOrder();

	public AuthorizeReturnObjectMethodInterceptor(AuthorizationProxyFactory authorizationProxyFactory) {
		Assert.notNull(authorizationProxyFactory, "authorizationManager cannot be null");
		this.authorizationProxyFactory = authorizationProxyFactory;
	}

	@Override
	public Object invoke(MethodInvocation mi) throws Throwable {
		Object result = mi.proceed();
		if (result == null) {
			return null;
		}
		return this.authorizationProxyFactory.proxy(result);
	}

	@Override
	public int getOrder() {
		return this.order;
	}

	public void setOrder(int order) {
		this.order = order;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Pointcut getPointcut() {
		return this.pointcut;
	}

	public void setPointcut(Pointcut pointcut) {
		this.pointcut = pointcut;
	}

	@Override
	public Advice getAdvice() {
		return this;
	}

	@Override
	public boolean isPerInstance() {
		return true;
	}

	static final class MethodReturnTypePointcut extends StaticMethodMatcherPointcut {

		private final Predicate<Class<?>> returnTypeMatches;

		MethodReturnTypePointcut(Predicate<Class<?>> returnTypeMatches) {
			this.returnTypeMatches = returnTypeMatches;
		}

		@Override
		public boolean matches(Method method, Class<?> targetClass) {
			return this.returnTypeMatches.test(method.getReturnType());
		}

	}

}
