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

package org.springframework.security.authentication;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationConvention;
import io.micrometer.observation.ObservationRegistry;
import io.micrometer.observation.contextpropagation.ObservationThreadLocalAccessor;
import reactor.core.publisher.Mono;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.Assert;

/**
 * An {@link ReactiveAuthenticationManager} that observes the authentication
 *
 * @author Josh Cummings
 * @since 6.0
 */
public class ObservationReactiveAuthenticationManager implements ReactiveAuthenticationManager {

	private final ObservationRegistry registry;

	private final ReactiveAuthenticationManager delegate;

	private ObservationConvention<AuthenticationObservationContext> convention = new AuthenticationObservationConvention();

	public ObservationReactiveAuthenticationManager(ObservationRegistry registry,
			ReactiveAuthenticationManager delegate) {
		this.registry = registry;
		this.delegate = delegate;
	}

	@Override
	public Mono<Authentication> authenticate(Authentication authentication) throws AuthenticationException {
		AuthenticationObservationContext context = new AuthenticationObservationContext();
		context.setAuthenticationRequest(authentication);
		context.setAuthenticationManagerClass(this.delegate.getClass());
		return Mono.deferContextual((contextView) -> {
			Observation observation = Observation.createNotStarted(this.convention, () -> context, this.registry)
				.parentObservation(contextView.getOrDefault(ObservationThreadLocalAccessor.KEY, null))
				.start();
			return this.delegate.authenticate(authentication).doOnSuccess((result) -> {
				context.setAuthenticationResult(result);
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
	public void setObservationConvention(ObservationConvention<AuthenticationObservationContext> convention) {
		Assert.notNull(convention, "The observation convention cannot be null");
		this.convention = convention;
	}

}
