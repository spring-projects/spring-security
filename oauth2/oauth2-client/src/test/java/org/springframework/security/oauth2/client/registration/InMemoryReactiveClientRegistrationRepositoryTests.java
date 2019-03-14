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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HashMap;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import reactor.test.StepVerifier;

/**
 * @author Rob Winch
 * @author Vedran Pavic
 * @since 5.1
 */
public class InMemoryReactiveClientRegistrationRepositoryTests {

	private ClientRegistration registration = TestClientRegistrations.clientRegistration().build();

	private InMemoryReactiveClientRegistrationRepository repository;

	@Before
	public void setup() {
		this.repository = new InMemoryReactiveClientRegistrationRepository(this.registration);
	}

	@Test
	public void constructorWhenZeroVarArgsThenIllegalArgumentException() {
		assertThatThrownBy(() -> new InMemoryReactiveClientRegistrationRepository())
			.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenClientRegistrationArrayThenIllegalArgumentException() {
		ClientRegistration[] registrations = null;
		assertThatThrownBy(() -> new InMemoryReactiveClientRegistrationRepository(registrations))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenClientRegistrationListThenIllegalArgumentException() {
		List<ClientRegistration> registrations = null;
		assertThatThrownBy(() -> new InMemoryReactiveClientRegistrationRepository(registrations))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenClientRegistrationListHasNullThenIllegalArgumentException() {
		List<ClientRegistration> registrations = Arrays.asList(null, registration);
		assertThatThrownBy(() -> new InMemoryReactiveClientRegistrationRepository(registrations))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenClientRegistrationIsNullThenIllegalArgumentException() {
		assertThatThrownBy(() -> new InMemoryReactiveClientRegistrationRepository(registration, null))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenClientRegistrationMapIsNullThenIllegalArgumentException() {
		Map<String, ClientRegistration> registrations = null;
		assertThatThrownBy(() -> new InMemoryReactiveClientRegistrationRepository(registrations))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenClientRegistrationMapIsEmptyThenRepositoryIsEmpty() {
		InMemoryReactiveClientRegistrationRepository repository = new InMemoryReactiveClientRegistrationRepository(
				new HashMap<>());
		assertThat(repository).isEmpty();
	}

	@Test
	public void findByRegistrationIdWhenValidIdThenFound() {
		StepVerifier.create(this.repository.findByRegistrationId(this.registration.getRegistrationId()))
				.expectNext(this.registration)
				.verifyComplete();
	}

	@Test
	public void findByRegistrationIdWhenNotValidIdThenEmpty() {
		StepVerifier.create(this.repository.findByRegistrationId(this.registration.getRegistrationId() + "invalid"))
				.verifyComplete();
	}

	@Test
	public void iteratorWhenContainsGithubThenContains() {
		assertThat(this.repository.iterator())
			.containsOnly(this.registration);
	}
}
