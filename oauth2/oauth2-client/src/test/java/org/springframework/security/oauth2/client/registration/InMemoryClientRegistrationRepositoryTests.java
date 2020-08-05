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

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link InMemoryClientRegistrationRepository}.
 *
 * @author Rob Winch
 * @author Vedran Pavic
 * @since 5.0
 */
public class InMemoryClientRegistrationRepositoryTests {

	private ClientRegistration registration = TestClientRegistrations.clientRegistration().build();

	private InMemoryClientRegistrationRepository clients = new InMemoryClientRegistrationRepository(this.registration);

	@Test(expected = IllegalArgumentException.class)
	public void constructorListClientRegistrationWhenNullThenIllegalArgumentException() {
		List<ClientRegistration> registrations = null;
		new InMemoryClientRegistrationRepository(registrations);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorListClientRegistrationWhenEmptyThenIllegalArgumentException() {
		List<ClientRegistration> registrations = Collections.emptyList();
		new InMemoryClientRegistrationRepository(registrations);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorMapClientRegistrationWhenNullThenIllegalArgumentException() {
		new InMemoryClientRegistrationRepository((Map<String, ClientRegistration>) null);
	}

	@Test
	public void constructorMapClientRegistrationWhenEmptyMapThenRepositoryIsEmpty() {
		InMemoryClientRegistrationRepository clients = new InMemoryClientRegistrationRepository(new HashMap<>());
		assertThat(clients).isEmpty();
	}

	@Test(expected = IllegalStateException.class)
	public void constructorListClientRegistrationWhenDuplicateIdThenIllegalArgumentException() {
		List<ClientRegistration> registrations = Arrays.asList(this.registration, this.registration);
		new InMemoryClientRegistrationRepository(registrations);
	}

	@Test
	public void findByRegistrationIdWhenFoundThenFound() {
		String id = this.registration.getRegistrationId();
		assertThat(this.clients.findByRegistrationId(id)).isEqualTo(this.registration);
	}

	@Test
	public void findByRegistrationIdWhenNotFoundThenNull() {
		String id = this.registration.getRegistrationId() + "MISSING";
		assertThat(this.clients.findByRegistrationId(id)).isNull();
	}

	@Test(expected = IllegalArgumentException.class)
	public void findByRegistrationIdWhenNullIdThenIllegalArgumentException() {
		String id = null;
		assertThat(this.clients.findByRegistrationId(id));
	}

	@Test(expected = UnsupportedOperationException.class)
	public void iteratorWhenRemoveThenThrowsUnsupportedOperationException() {
		this.clients.iterator().remove();
	}

	@Test
	public void iteratorWhenGetThenContainsAll() {
		assertThat(this.clients).containsOnly(this.registration);
	}

}
