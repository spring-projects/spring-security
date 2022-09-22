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

import java.util.function.Supplier;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;

/**
 * An {@link AuthorizationManager} that observes the authorization
 *
 * @author Josh Cummings
 * @since 6.0
 */
public final class ObservationAuthorizationManager<T> implements AuthorizationManager<T> {

	private final ObservationRegistry registry;

	private final AuthorizationManager<T> delegate;

	private final AuthorizationObservationConvention convention = new AuthorizationObservationConvention();

	public ObservationAuthorizationManager(ObservationRegistry registry, AuthorizationManager<T> delegate) {
		this.registry = registry;
		this.delegate = delegate;
	}

	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, T object) {
		AuthorizationObservationContext<T> context = new AuthorizationObservationContext<>(object);
		Supplier<Authentication> wrapped = () -> {
			context.setAuthentication(authentication.get());
			return context.getAuthentication();
		};
		Observation observation = Observation.createNotStarted(this.convention, () -> context, this.registry).start();
		try (Observation.Scope scope = observation.openScope()) {
			AuthorizationDecision decision = this.delegate.check(wrapped, object);
			context.setDecision(decision);
			if (decision != null && !decision.isGranted()) {
				observation.error(new AccessDeniedException("Access Denied"));
			}
			return decision;
		}
		catch (Throwable ex) {
			observation.error(ex);
			throw ex;
		}
		finally {
			observation.stop();
		}
	}

}
