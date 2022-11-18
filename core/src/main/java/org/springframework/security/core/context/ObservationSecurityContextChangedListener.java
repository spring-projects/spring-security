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

package org.springframework.security.core.context;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;

import org.springframework.security.core.Authentication;

/**
 * A {@link SecurityContextChangedListener} that adds events to an existing
 * {@link Observation}
 *
 * If no {@link Observation} is present when an event is fired, then the event is
 * unrecorded.
 *
 * @author Josh Cummings
 * @since 6.0
 */
public final class ObservationSecurityContextChangedListener implements SecurityContextChangedListener {

	static final String SECURITY_CONTEXT_CREATED = "spring.security.context.created";

	static final String SECURITY_CONTEXT_CHANGED = "spring.security.context.changed";

	static final String SECURITY_CONTEXT_CLEARED = "spring.security.context.cleared";

	private final ObservationRegistry registry;

	/**
	 * Create a {@link ObservationSecurityContextChangedListener}
	 * @param registry the {@link ObservationRegistry} for looking up the surrounding
	 * {@link Observation}
	 */
	public ObservationSecurityContextChangedListener(ObservationRegistry registry) {
		this.registry = registry;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void securityContextChanged(SecurityContextChangedEvent event) {
		Observation observation = this.registry.getCurrentObservation();
		if (observation == null) {
			return;
		}
		if (event.isCleared()) {
			observation.event(Observation.Event.of(SECURITY_CONTEXT_CLEARED));
			return;
		}
		Authentication oldAuthentication = getAuthentication(event.getOldContext());
		Authentication newAuthentication = getAuthentication(event.getNewContext());
		if (oldAuthentication == null && newAuthentication == null) {
			return;
		}
		if (oldAuthentication == null) {
			observation.event(Observation.Event.of(SECURITY_CONTEXT_CREATED, "%s [%s]").format(SECURITY_CONTEXT_CREATED,
					newAuthentication.getClass().getSimpleName()));
			return;
		}
		if (newAuthentication == null) {
			observation.event(Observation.Event.of(SECURITY_CONTEXT_CLEARED, "%s [%s]").format(SECURITY_CONTEXT_CLEARED,
					oldAuthentication.getClass().getSimpleName()));
			return;
		}
		if (oldAuthentication.equals(newAuthentication)) {
			return;
		}
		observation.event(
				Observation.Event.of(SECURITY_CONTEXT_CHANGED, "%s [%s] -> [%s]").format(SECURITY_CONTEXT_CHANGED,
						oldAuthentication.getClass().getSimpleName(), newAuthentication.getClass().getSimpleName()));
	}

	private static Authentication getAuthentication(SecurityContext context) {
		if (context == null) {
			return null;
		}
		return context.getAuthentication();
	}

}
