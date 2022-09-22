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

package org.springframework.security.authorization;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;
import reactor.core.publisher.Mono;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;

/**
 * An {@link ReactiveAuthorizationManager} that observes the authentication
 *
 * @author Josh Cummings
 * @since 6.0
 */
public final class ObservationReactiveAuthorizationManager<T> implements ReactiveAuthorizationManager<T> {

	private final ObservationRegistry registry;

	private final ReactiveAuthorizationManager<T> delegate;

	private final AuthorizationObservationConvention convention = new AuthorizationObservationConvention();

	public ObservationReactiveAuthorizationManager(ObservationRegistry registry,
			ReactiveAuthorizationManager<T> delegate) {
		this.registry = registry;
		this.delegate = delegate;
	}

	@Override
	public Mono<AuthorizationDecision> check(Mono<Authentication> authentication, T object) {
		AuthorizationObservationContext<T> context = new AuthorizationObservationContext<>(object);
		Mono<Authentication> wrapped = authentication.map((auth) -> {
			context.setAuthentication(auth);
			return context.getAuthentication();
		});
		Observation observation = Observation.createNotStarted(this.convention, () -> context, this.registry).start();
		return this.delegate.check(wrapped, object).doOnSuccess((decision) -> {
			context.setDecision(decision);
			if (decision == null || !decision.isGranted()) {
				observation.error(new AccessDeniedException("Access Denied"));
			}
			observation.stop();
		}).doOnCancel(observation::stop).doOnError((t) -> {
			observation.error(t);
			observation.stop();
		});
	}

}
