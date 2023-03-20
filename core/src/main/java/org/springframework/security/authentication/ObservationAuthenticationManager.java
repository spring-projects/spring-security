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

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationManager} that observes the authentication
 *
 * @author Josh Cummings
 * @since 6.0
 */
public final class ObservationAuthenticationManager implements AuthenticationManager {

	private final ObservationRegistry registry;

	private final AuthenticationManager delegate;

	private final AuthenticationObservationConvention convention = new AuthenticationObservationConvention();

	public ObservationAuthenticationManager(ObservationRegistry registry, AuthenticationManager delegate) {
		Assert.notNull(registry, "observationRegistry cannot be null");
		Assert.notNull(delegate, "authenticationManager cannot be null");
		this.registry = registry;
		this.delegate = delegate;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		AuthenticationObservationContext context = new AuthenticationObservationContext();
		context.setAuthenticationRequest(authentication);
		context.setAuthenticationManagerClass(this.delegate.getClass());
		return Observation.createNotStarted(this.convention, () -> context, this.registry).observe(() -> {
			Authentication result = this.delegate.authenticate(authentication);
			context.setAuthenticationResult(result);
			return result;
		});
	}

}
