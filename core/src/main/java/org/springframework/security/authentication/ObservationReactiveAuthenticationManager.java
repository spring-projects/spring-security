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

package org.springframework.security.authentication;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;
import reactor.core.publisher.Mono;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * An {@link ReactiveAuthenticationManager} that observes the authentication
 *
 * @author Josh Cummings
 * @since 6.0
 */
public class ObservationReactiveAuthenticationManager implements ReactiveAuthenticationManager {

	private final ObservationRegistry registry;

	private final ReactiveAuthenticationManager delegate;

	private final AuthenticationObservationConvention convention = new AuthenticationObservationConvention();

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
		Observation observation = Observation.createNotStarted(this.convention, () -> context, this.registry).start();
		return this.delegate.authenticate(authentication).doOnSuccess((result) -> {
			context.setAuthenticationResult(result);
			observation.stop();
		}).doOnCancel(observation::stop).doOnError((t) -> {
			observation.error(t);
			observation.stop();
		});
	}

}
