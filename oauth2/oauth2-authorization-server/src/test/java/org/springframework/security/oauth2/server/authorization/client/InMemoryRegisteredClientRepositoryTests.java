/*
 * Copyright 2020-2023 the original author or authors.
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
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link InMemoryRegisteredClientRepository}.
 *
 * @author Anoop Garlapati
 * @author Ovidiu Popa
 * @author Joe Grandja
 */
public class InMemoryRegisteredClientRepositoryTests {

	private RegisteredClient registration = TestRegisteredClients.registeredClient().build();

	private InMemoryRegisteredClientRepository clients = new InMemoryRegisteredClientRepository(this.registration);

	@Test
	public void constructorVarargsRegisteredClientWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> {
			RegisteredClient registration = null;
			new InMemoryRegisteredClientRepository(registration);
		}).withMessageContaining("registration cannot be null");
	}

	@Test
	public void constructorListRegisteredClientWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> {
			List<RegisteredClient> registrations = null;
			new InMemoryRegisteredClientRepository(registrations);
		}).withMessageContaining("registrations cannot be empty");
	}

	@Test
	public void constructorListRegisteredClientWhenEmptyThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> {
			List<RegisteredClient> registrations = Collections.emptyList();
			new InMemoryRegisteredClientRepository(registrations);
		}).withMessageContaining("registrations cannot be empty");
	}

	@Test
	public void constructorListRegisteredClientWhenDuplicateIdThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> {
			RegisteredClient anotherRegistrationWithSameId = TestRegisteredClients.registeredClient2()
				.id(this.registration.getId())
				.build();
			List<RegisteredClient> registrations = Arrays.asList(this.registration, anotherRegistrationWithSameId);
			new InMemoryRegisteredClientRepository(registrations);
		}).withMessageStartingWith("Registered client must be unique. Found duplicate identifier:");
	}

	@Test
	public void constructorListRegisteredClientWhenDuplicateClientIdThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> {
			RegisteredClient anotherRegistrationWithSameClientId = TestRegisteredClients.registeredClient2()
				.clientId(this.registration.getClientId())
				.build();
			List<RegisteredClient> registrations = Arrays.asList(this.registration,
					anotherRegistrationWithSameClientId);
			new InMemoryRegisteredClientRepository(registrations);
		}).withMessageStartingWith("Registered client must be unique. Found duplicate client identifier:");
	}

	@Test
	public void constructorListRegisteredClientWhenDuplicateClientSecretThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> {
			RegisteredClient anotherRegistrationWithSameClientSecret = TestRegisteredClients.registeredClient2()
				.clientSecret(this.registration.getClientSecret())
				.build();
			List<RegisteredClient> registrations = Arrays.asList(this.registration,
					anotherRegistrationWithSameClientSecret);
			new InMemoryRegisteredClientRepository(registrations);
		}).withMessageStartingWith("Registered client must be unique. Found duplicate client secret for identifier:");
	}

	@Test
	public void findByIdWhenFoundThenFound() {
		String id = this.registration.getId();
		assertThat(this.clients.findById(id)).isEqualTo(this.registration);
	}

	@Test
	public void findByIdWhenNotFoundThenNull() {
		String missingId = this.registration.getId() + "MISSING";
		assertThat(this.clients.findById(missingId)).isNull();
	}

	@Test
	public void findByIdWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.clients.findById(null))
			.withMessageContaining("id cannot be empty");
	}

	@Test
	public void findByClientIdWhenFoundThenFound() {
		String clientId = this.registration.getClientId();
		assertThat(this.clients.findByClientId(clientId)).isEqualTo(this.registration);
	}

	@Test
	public void findByClientIdWhenNotFoundThenNull() {
		String missingClientId = this.registration.getClientId() + "MISSING";
		assertThat(this.clients.findByClientId(missingClientId)).isNull();
	}

	@Test
	public void findByClientIdWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.clients.findByClientId(null))
			.withMessageContaining("clientId cannot be empty");
	}

	@Test
	public void saveWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.clients.save(null))
			.withMessageContaining("registeredClient cannot be null");
	}

	@Test
	public void saveWhenExistingIdThenUpdate() {
		RegisteredClient registeredClient = createRegisteredClient(this.registration.getId(), "client-id-2",
				"client-secret-2");
		this.clients.save(registeredClient);
		RegisteredClient savedClient = this.clients.findByClientId(registeredClient.getClientId());
		assertThat(savedClient).isEqualTo(registeredClient);
	}

	@Test
	public void saveWhenExistingClientIdThenThrowIllegalArgumentException() {
		RegisteredClient registeredClient = createRegisteredClient("client-2", this.registration.getClientId(),
				"client-secret-2");
		assertThatIllegalArgumentException().isThrownBy(() -> this.clients.save(registeredClient))
			.withMessage("Registered client must be unique. Found duplicate client identifier: "
					+ registeredClient.getClientId());
	}

	@Test
	public void saveWhenExistingClientSecretThenThrowIllegalArgumentException() {
		RegisteredClient registeredClient = createRegisteredClient("client-2", "client-id-2",
				this.registration.getClientSecret());
		assertThatIllegalArgumentException().isThrownBy(() -> this.clients.save(registeredClient))
			.withMessage("Registered client must be unique. Found duplicate client secret for identifier: "
					+ registeredClient.getId());
	}

	@Test
	public void saveWhenSavedAndFindByIdThenFound() {
		RegisteredClient registeredClient = createRegisteredClient();
		this.clients.save(registeredClient);
		RegisteredClient savedClient = this.clients.findById(registeredClient.getId());
		assertThat(savedClient).isEqualTo(registeredClient);
	}

	@Test
	public void saveWhenSavedAndFindByClientIdThenFound() {
		RegisteredClient registeredClient = createRegisteredClient();
		this.clients.save(registeredClient);
		RegisteredClient savedClient = this.clients.findByClientId(registeredClient.getClientId());
		assertThat(savedClient).isEqualTo(registeredClient);
	}

	private static RegisteredClient createRegisteredClient() {
		return createRegisteredClient("client-2", "client-id-2", "client-secret-2");
	}

	private static RegisteredClient createRegisteredClient(String id, String clientId, String clientSecret) {
		// @formatter:off
		return RegisteredClient.withId(id)
				.clientId(clientId)
				.clientSecret(clientSecret)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.redirectUri("https://client.example.com")
				.scope("scope1")
				.build();
		// @formatter:on
	}

}
