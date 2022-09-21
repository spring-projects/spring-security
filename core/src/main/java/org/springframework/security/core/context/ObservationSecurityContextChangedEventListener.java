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

	private final ObservationRegistry registry;

	public ObservationSecurityContextChangedEventListener(ObservationRegistry registry) {
		this.registry = registry;
	}

	@Override
	public void securityContextChanged(SecurityContextChangedEvent event) {
		Observation observation = this.registry.getCurrentObservation();
		if (observation == null) {
			return;
		}
		if (event.isContextCleared()) {
			observation.event(Observation.Event.of("security.context.cleared"));
			return;
		}
		Authentication oldAuthentication = getAuthentication(event.getOldContext());
		Authentication newAuthentication = getAuthentication(event.getNewContext());
		if (oldAuthentication == null && newAuthentication == null) {
			return;
		}
		if (oldAuthentication == null) {
			observation.event(Observation.Event.of("security.context.started",
					"security.context.started [" + oldAuthentication.getAuthenticationType() + "]"));
			return;
		}
		if (newAuthentication == null) {
			observation.event(Observation.Event.of("security.context.cleared",
					"security.context.cleared [" + oldAuthentication.getAuthenticationType() + "]"));
			return;
		}
		observation.event(Observation.Event.of("security.context.replaced",
				"security.context.replaced [" + newAuthentication.getAuthenticationType() + "] -> ["
						+ newAuthentication.getAuthenticationType() + "]"));
	}

	private static Authentication getAuthentication(SecurityContext context) {
		if (context == null) {
			return null;
		}
		return context.getAuthentication();
	}

}
