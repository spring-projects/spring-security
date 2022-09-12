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

public class ObservationSecurityContextChangedEventListener implements SecurityContextChangedListener {

	private static final String SECURITY_CONTEXT_OBSERVATION_NAME = "with.security.context";

	private final ObservationRegistry registry;

	public ObservationSecurityContextChangedEventListener(ObservationRegistry registry) {
		this.registry = registry;
	}

	@Override
	public void securityContextChanged(SecurityContextChangedEvent event) {
		if (event.getDeferredNewContext() == null) {
			closeObservation();
			return;
		}
		Authentication oldAuthentication = getAuthentication(event.getOldContext());
		Authentication newAuthentication = getAuthentication(event.getNewContext());
		if (newAuthentication == null) {
			return;
		}
		if (newAuthentication.equals(oldAuthentication)) {
			return;
		}
		replaceObservation();
	}

	private Observation.Scope ifSecurityScopeOpened() {
		Observation.Scope scope = this.registry.getCurrentObservationScope();
		if (scope == null) {
			return null;
		}
		Observation observation = scope.getCurrentObservation();
		String observationName = observation.getContext().getName();
		if (!SECURITY_CONTEXT_OBSERVATION_NAME.equals(observationName)) {
			return null;
		}
		return scope;
	}

	private void replaceObservation() {
		Observation.Scope scope = this.registry.getCurrentObservationScope();
		if (scope == null) {
			Observation.start(SECURITY_CONTEXT_OBSERVATION_NAME, this.registry).openScope();
			return;
		}
		Observation observation = scope.getCurrentObservation();
		String observationName = scope.getCurrentObservation().getContext().getName();
		if (!SECURITY_CONTEXT_OBSERVATION_NAME.equals(observationName)) {
			Observation.start(SECURITY_CONTEXT_OBSERVATION_NAME, this.registry).openScope();
			return;
		}
		scope.close();
		observation.stop();
		Observation.start(SECURITY_CONTEXT_OBSERVATION_NAME, this.registry).openScope();
	}

	private void closeObservation() {
		Observation.Scope scope = ifSecurityScopeOpened();
		if (scope == null) {
			return;
		}
		Observation observation = scope.getCurrentObservation();
		if (!SECURITY_CONTEXT_OBSERVATION_NAME.equals(observation.getContext().getName())) {
			return;
		}
		scope.close();
		observation.stop();
	}

	private static Authentication getAuthentication(SecurityContext context) {
		if (context == null) {
			return null;
		}
		return context.getAuthentication();
	}

}
