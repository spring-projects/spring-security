/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.oauth2.client.registration;

import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Function;
import java.util.stream.Collector;

import static java.util.stream.Collectors.collectingAndThen;
import static java.util.stream.Collectors.toConcurrentMap;

/**
 * A {@link ClientRegistrationRepository} that stores {@link ClientRegistration}(s) in-memory.
 *
 * @author Joe Grandja
 * @author Rob Winch
 * @author Vedran Pavic
 * @since 5.0
 * @see ClientRegistrationRepository
 * @see ClientRegistration
 */
public final class InMemoryClientRegistrationRepository implements ClientRegistrationRepository, Iterable<ClientRegistration> {
	private final Map<String, ClientRegistration> registrations;

	/**
	 * Constructs an {@code InMemoryClientRegistrationRepository} using the provided parameters.
	 *
	 * @param registrations the client registration(s)
	 */
	public InMemoryClientRegistrationRepository(ClientRegistration... registrations) {
		this(Arrays.asList(registrations));
	}

	/**
	 * Constructs an {@code InMemoryClientRegistrationRepository} using the provided parameters.
	 *
	 * @param registrations the client registration(s)
	 */
	public InMemoryClientRegistrationRepository(List<ClientRegistration> registrations) {
		this(createRegistrationsMap(registrations));
	}

	private static Map<String, ClientRegistration> createRegistrationsMap(List<ClientRegistration> registrations) {
		Assert.notEmpty(registrations, "registrations cannot be empty");
		Collector<ClientRegistration, ?, ConcurrentMap<String, ClientRegistration>> collector =
				toConcurrentMap(ClientRegistration::getRegistrationId, Function.identity());
		return registrations.stream().collect(collectingAndThen(collector, Collections::unmodifiableMap));
	}

	/**
	 * Constructs an {@code InMemoryClientRegistrationRepository} using the provided {@code Map}
	 * of {@link ClientRegistration#getRegistrationId() registration id} to {@link ClientRegistration}.
	 *
	 * @since 5.2
	 * @param registrations the {@code Map} of client registration(s)
	 */
	public InMemoryClientRegistrationRepository(Map<String, ClientRegistration> registrations) {
		Assert.notNull(registrations, "registrations cannot be null");
		this.registrations = registrations;
	}

	@Override
	public ClientRegistration findByRegistrationId(String registrationId) {
		Assert.hasText(registrationId, "registrationId cannot be empty");
		return this.registrations.get(registrationId);
	}

	/**
	 * Returns an {@code Iterator} of {@link ClientRegistration}.
	 *
	 * @return an {@code Iterator<ClientRegistration>}
	 */
	@Override
	public Iterator<ClientRegistration> iterator() {
		return this.registrations.values().iterator();
	}
}
