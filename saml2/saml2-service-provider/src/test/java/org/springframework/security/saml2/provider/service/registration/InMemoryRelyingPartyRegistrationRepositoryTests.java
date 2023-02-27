/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.saml2.provider.service.registration;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link InMemoryRelyingPartyRegistrationRepository}
 */
public class InMemoryRelyingPartyRegistrationRepositoryTests {

	@Test
	void findByRegistrationIdWhenGivenIdThenReturnsMatchingRegistration() {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.relyingPartyRegistration().build();
		InMemoryRelyingPartyRegistrationRepository registrations = new InMemoryRelyingPartyRegistrationRepository(
				registration);
		assertThat(registrations.findByRegistrationId(registration.getRegistrationId())).isSameAs(registration);
	}

	@Test
	void findByRegistrationIdWhenGivenWrongIdThenReturnsNull() {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.relyingPartyRegistration().build();
		InMemoryRelyingPartyRegistrationRepository registrations = new InMemoryRelyingPartyRegistrationRepository(
				registration);
		assertThat(registrations.findByRegistrationId(registration.getRegistrationId() + "wrong")).isNull();
		assertThat(registrations.findByRegistrationId(null)).isNull();
	}

	@Test
	void findByAssertingPartyEntityIdWhenGivenEntityIdThenReturnsMatchingRegistrations() {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.relyingPartyRegistration().build();
		InMemoryRelyingPartyRegistrationRepository registrations = new InMemoryRelyingPartyRegistrationRepository(
				registration);
		String assertingPartyEntityId = registration.getAssertingPartyDetails().getEntityId();
		assertThat(registrations.findUniqueByAssertingPartyEntityId(assertingPartyEntityId)).isEqualTo(registration);
	}

	@Test
	void findByAssertingPartyEntityIdWhenGivenWrongEntityIdThenReturnsEmpty() {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.relyingPartyRegistration().build();
		InMemoryRelyingPartyRegistrationRepository registrations = new InMemoryRelyingPartyRegistrationRepository(
				registration);
		String assertingPartyEntityId = registration.getAssertingPartyDetails().getEntityId();
		assertThat(registrations.findUniqueByAssertingPartyEntityId(assertingPartyEntityId + "wrong")).isNull();
	}

}
