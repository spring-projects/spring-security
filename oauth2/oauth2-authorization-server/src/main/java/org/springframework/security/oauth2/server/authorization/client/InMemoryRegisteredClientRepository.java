/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.server.authorization.client;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.lang.Nullable;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * A {@link RegisteredClientRepository} that stores {@link RegisteredClient}(s) in-memory.
 *
 * <p>
 * <b>NOTE:</b> This implementation is recommended ONLY to be used during
 * development/testing.
 *
 * @author Anoop Garlapati
 * @author Ovidiu Popa
 * @author Joe Grandja
 * @since 7.0
 * @see RegisteredClientRepository
 * @see RegisteredClient
 */
public final class InMemoryRegisteredClientRepository implements RegisteredClientRepository {

	private final Map<String, RegisteredClient> idRegistrationMap;

	private final Map<String, RegisteredClient> clientIdRegistrationMap;

	/**
	 * Constructs an {@code InMemoryRegisteredClientRepository} using the provided
	 * parameters.
	 * @param registrations the client registration(s)
	 */
	public InMemoryRegisteredClientRepository(RegisteredClient... registrations) {
		this(Arrays.asList(registrations));
	}

	/**
	 * Constructs an {@code InMemoryRegisteredClientRepository} using the provided
	 * parameters.
	 * @param registrations the client registration(s)
	 */
	public InMemoryRegisteredClientRepository(List<RegisteredClient> registrations) {
		Assert.notEmpty(registrations, "registrations cannot be empty");
		ConcurrentHashMap<String, RegisteredClient> idRegistrationMapResult = new ConcurrentHashMap<>();
		ConcurrentHashMap<String, RegisteredClient> clientIdRegistrationMapResult = new ConcurrentHashMap<>();
		for (RegisteredClient registration : registrations) {
			Assert.notNull(registration, "registration cannot be null");
			assertUniqueIdentifiers(registration, idRegistrationMapResult);
			idRegistrationMapResult.put(registration.getId(), registration);
			clientIdRegistrationMapResult.put(registration.getClientId(), registration);
		}
		this.idRegistrationMap = idRegistrationMapResult;
		this.clientIdRegistrationMap = clientIdRegistrationMapResult;
	}

	@Override
	public void save(RegisteredClient registeredClient) {
		Assert.notNull(registeredClient, "registeredClient cannot be null");
		if (!this.idRegistrationMap.containsKey(registeredClient.getId())) {
			assertUniqueIdentifiers(registeredClient, this.idRegistrationMap);
		}
		this.idRegistrationMap.put(registeredClient.getId(), registeredClient);
		this.clientIdRegistrationMap.put(registeredClient.getClientId(), registeredClient);
	}

	@Nullable
	@Override
	public RegisteredClient findById(String id) {
		Assert.hasText(id, "id cannot be empty");
		return this.idRegistrationMap.get(id);
	}

	@Nullable
	@Override
	public RegisteredClient findByClientId(String clientId) {
		Assert.hasText(clientId, "clientId cannot be empty");
		return this.clientIdRegistrationMap.get(clientId);
	}

	private void assertUniqueIdentifiers(RegisteredClient registeredClient,
			Map<String, RegisteredClient> registrations) {
		registrations.values().forEach((registration) -> {
			if (registeredClient.getId().equals(registration.getId())) {
				throw new IllegalArgumentException("Registered client must be unique. " + "Found duplicate identifier: "
						+ registeredClient.getId());
			}
			if (registeredClient.getClientId().equals(registration.getClientId())) {
				throw new IllegalArgumentException("Registered client must be unique. "
						+ "Found duplicate client identifier: " + registeredClient.getClientId());
			}
			if (StringUtils.hasText(registeredClient.getClientSecret())
					&& registeredClient.getClientSecret().equals(registration.getClientSecret())) {
				throw new IllegalArgumentException("Registered client must be unique. "
						+ "Found duplicate client secret for identifier: " + registeredClient.getId());
			}
		});
	}

}
