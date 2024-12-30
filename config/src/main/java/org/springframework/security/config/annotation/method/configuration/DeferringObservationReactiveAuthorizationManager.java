/*
 * Copyright 2002-2023 the original author or authors.
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

import io.micrometer.observation.ObservationRegistry;
import org.aopalliance.intercept.MethodInvocation;
import reactor.core.publisher.Mono;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.ObservationReactiveAuthorizationManager;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.authorization.method.MethodAuthorizationDeniedHandler;
import org.springframework.security.authorization.method.MethodInvocationResult;
import org.springframework.security.authorization.method.ThrowingMethodAuthorizationDeniedHandler;
import org.springframework.security.core.Authentication;
import org.springframework.util.function.SingletonSupplier;

final class DeferringObservationReactiveAuthorizationManager<T>
		implements ReactiveAuthorizationManager<T>, MethodAuthorizationDeniedHandler {

	private final Supplier<ReactiveAuthorizationManager<T>> delegate;

	private MethodAuthorizationDeniedHandler handler = new ThrowingMethodAuthorizationDeniedHandler();

	DeferringObservationReactiveAuthorizationManager(ObjectProvider<ObservationRegistry> provider,
			ReactiveAuthorizationManager<T> delegate) {
		this.delegate = SingletonSupplier.of(() -> {
			ObservationRegistry registry = provider.getIfAvailable(() -> ObservationRegistry.NOOP);
			if (registry.isNoop()) {
				return delegate;
			}
			return new ObservationReactiveAuthorizationManager<>(registry, delegate);
		});
		if (delegate instanceof MethodAuthorizationDeniedHandler h) {
			this.handler = h;
		}
	}

	@Override
	public Mono<AuthorizationDecision> check(Mono<Authentication> authentication, T object) {
		return this.delegate.get().check(authentication, object);
	}

	@Override
	public Object handleDeniedInvocation(MethodInvocation methodInvocation, AuthorizationResult authorizationResult) {
		return this.handler.handleDeniedInvocation(methodInvocation, authorizationResult);
	}

	@Override
	public Object handleDeniedInvocationResult(MethodInvocationResult methodInvocationResult,
			AuthorizationResult authorizationResult) {
		return this.handler.handleDeniedInvocationResult(methodInvocationResult, authorizationResult);
	}

}
