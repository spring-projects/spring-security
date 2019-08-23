/*
 * Copyright 2002-2019 the original author or authors.
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

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.util.Assert;

import reactor.core.publisher.Mono;

/**
 * A Reactive {@link ClientRegistrationRepository} that stores {@link ClientRegistration}(s) in-memory.
 *
 * @author Rob Winch
 * @author Ebert Toribio
 * @since 5.1
 * @see ClientRegistrationRepository
 * @see ClientRegistration
 */
public final class InMemoryReactiveClientRegistrationRepository
		implements ReactiveClientRegistrationRepository, Iterable<ClientRegistration> {

	private final Map<String, ClientRegistration> clientIdToClientRegistration;

	/**
	 * Constructs an {@code InMemoryReactiveClientRegistrationRepository} using the provided parameters.
	 *
	 * @param registrations the client registration(s)
	 */
	public InMemoryReactiveClientRegistrationRepository(ClientRegistration... registrations) {
		Assert.notEmpty(registrations, "registrations cannot be empty");
		this.clientIdToClientRegistration = new ConcurrentHashMap<>();
		for (ClientRegistration registration : registrations) {
			Assert.notNull(registration, "registrations cannot contain null values");
			this.clientIdToClientRegistration.put(registration.getRegistrationId(), registration);
		}
	}

	/**
	 * Constructs an {@code InMemoryReactiveClientRegistrationRepository} using the provided parameters.
	 *
	 * @param registrations the client registration(s)
	 */
	public InMemoryReactiveClientRegistrationRepository(List<ClientRegistration> registrations) {
		Assert.notEmpty(registrations, "registrations cannot be null or empty");
		this.clientIdToClientRegistration = registrations.stream()
				.collect(Collectors.toConcurrentMap(ClientRegistration::getRegistrationId, Function.identity()));
	}


	@Override
	public Mono<ClientRegistration> findByRegistrationId(String registrationId) {
		return Mono.justOrEmpty(this.clientIdToClientRegistration.get(registrationId));
	}

	/**
	 * Returns an {@code Iterator} of {@link ClientRegistration}.
	 *
	 * @return an {@code Iterator<ClientRegistration>}
	 */
	@Override
	public Iterator<ClientRegistration> iterator() {
		return this.clientIdToClientRegistration.values().iterator();
	}
}
