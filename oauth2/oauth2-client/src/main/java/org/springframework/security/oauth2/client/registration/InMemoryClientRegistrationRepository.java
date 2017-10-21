/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.registration;

import org.springframework.util.Assert;

import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A {@link ClientRegistrationRepository} that stores {@link ClientRegistration}(s) <i>in-memory</i>.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see ClientRegistrationRepository
 * @see ClientRegistration
 */
public final class InMemoryClientRegistrationRepository implements ClientRegistrationRepository, Iterable<ClientRegistration> {
	private final Map<String, ClientRegistration> registrations;

	public InMemoryClientRegistrationRepository(List<ClientRegistration> registrations) {
		Assert.notEmpty(registrations, "registrations cannot be empty");
		Map<String, ClientRegistration> registrationsMap = new ConcurrentHashMap<>();
		registrations.forEach(registration -> {
			if (registrationsMap.containsKey(registration.getRegistrationId())) {
				throw new IllegalArgumentException("ClientRegistration must be unique. Found duplicate registrationId: " +
					registration.getRegistrationId());
			}
			registrationsMap.put(registration.getRegistrationId(), registration);
		});
		this.registrations = Collections.unmodifiableMap(registrationsMap);
	}

	@Override
	public ClientRegistration findByRegistrationId(String registrationId) {
		Assert.hasText(registrationId, "registrationId cannot be empty");
		return this.registrations.values().stream()
			.filter(registration -> registration.getRegistrationId().equals(registrationId))
			.findFirst()
			.orElse(null);
	}

	@Override
	public Iterator<ClientRegistration> iterator() {
		return Collections.unmodifiableCollection(this.registrations.values()).iterator();
	}
}
