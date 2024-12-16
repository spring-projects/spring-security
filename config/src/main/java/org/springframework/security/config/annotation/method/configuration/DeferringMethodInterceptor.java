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

package org.springframework.security.config.annotation.method.configuration;

import java.util.function.Supplier;

import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInvocation;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import org.springframework.aop.Pointcut;
import org.springframework.security.authorization.method.AuthorizationAdvisor;
import org.springframework.util.function.SingletonSupplier;

final class DeferringMethodInterceptor<M extends AuthorizationAdvisor> implements AuthorizationAdvisor {

	private final Pointcut pointcut;

	private final Supplier<M> delegate;

	DeferringMethodInterceptor(Pointcut pointcut, Supplier<M> delegate) {
		this.pointcut = pointcut;
		this.delegate = SingletonSupplier.of(delegate);
	}

	@Nullable
	@Override
	public Object invoke(@NotNull MethodInvocation invocation) throws Throwable {
		return this.delegate.get().invoke(invocation);
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
	public int getOrder() {
		return this.delegate.get().getOrder();
	}

	@Override
	public boolean isPerInstance() {
		return true;
	}

}
