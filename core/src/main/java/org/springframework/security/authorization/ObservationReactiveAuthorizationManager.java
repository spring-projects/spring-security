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

package org.springframework.security.authorization;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationConvention;
import io.micrometer.observation.ObservationRegistry;
import io.micrometer.observation.contextpropagation.ObservationThreadLocalAccessor;
import org.aopalliance.intercept.MethodInvocation;
import reactor.core.publisher.Mono;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.method.MethodAuthorizationDeniedHandler;
import org.springframework.security.authorization.method.MethodInvocationResult;
import org.springframework.security.authorization.method.ThrowingMethodAuthorizationDeniedHandler;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * An {@link ReactiveAuthorizationManager} that observes the authentication
 *
 * @author Josh Cummings
 * @since 6.0
 */
public final class ObservationReactiveAuthorizationManager<T>
		implements ReactiveAuthorizationManager<T>, MethodAuthorizationDeniedHandler {

	private final ObservationRegistry registry;

	private final ReactiveAuthorizationManager<T> delegate;

	private ObservationConvention<AuthorizationObservationContext<?>> convention = new AuthorizationObservationConvention();

	private MethodAuthorizationDeniedHandler handler = new ThrowingMethodAuthorizationDeniedHandler();

	public ObservationReactiveAuthorizationManager(ObservationRegistry registry,
			ReactiveAuthorizationManager<T> delegate) {
		this.registry = registry;
		this.delegate = delegate;
		if (delegate instanceof MethodAuthorizationDeniedHandler h) {
			this.handler = h;
		}
	}

	/**
	 * @deprecated please use {@link #authorize(Mono, Object)} instead
	 */
	@Deprecated
	@Override
	public Mono<AuthorizationDecision> check(Mono<Authentication> authentication, T object) {
		AuthorizationObservationContext<T> context = new AuthorizationObservationContext<>(object);
		Mono<Authentication> wrapped = authentication.map((auth) -> {
			context.setAuthentication(auth);
			return context.getAuthentication();
		});
		return Mono.deferContextual((contextView) -> {
			Observation observation = Observation.createNotStarted(this.convention, () -> context, this.registry)
				.parentObservation(contextView.getOrDefault(ObservationThreadLocalAccessor.KEY, null))
				.start();
			return this.delegate.check(wrapped, object).doOnSuccess((decision) -> {
				context.setAuthorizationResult(decision);
				if (decision == null || !decision.isGranted()) {
					observation.error(new AccessDeniedException("Access Denied"));
				}
				observation.stop();
			}).doOnCancel(observation::stop).doOnError((t) -> {
				observation.error(t);
				observation.stop();
			});
		});
	}

	/**
	 * Use the provided convention for reporting observation data
	 * @param convention The provided convention
	 *
	 * @since 6.1
	 */
	public void setObservationConvention(ObservationConvention<AuthorizationObservationContext<?>> convention) {
		Assert.notNull(convention, "The observation convention cannot be null");
		this.convention = convention;
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
