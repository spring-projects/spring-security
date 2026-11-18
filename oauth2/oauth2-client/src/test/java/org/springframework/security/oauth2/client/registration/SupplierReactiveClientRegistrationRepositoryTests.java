/*
 * Copyright 2002-2025 the original author or authors.
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

import java.util.function.Supplier;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link SupplierReactiveClientRegistrationRepository}.
 *
 * @author Max Batischev
 */
@ExtendWith(MockitoExtension.class)
public class SupplierReactiveClientRegistrationRepositoryTests {

	private final ClientRegistration registration = TestClientRegistrations.clientRegistration().build();

	private final SupplierReactiveClientRegistrationRepository registrationRepository = new SupplierReactiveClientRegistrationRepository(
			() -> new InMemoryReactiveClientRegistrationRepository(this.registration));

	@Mock
	private Supplier<InMemoryReactiveClientRegistrationRepository> clientRegistrationRepositorySupplier;

	@Test
	void constructWhenNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new SupplierReactiveClientRegistrationRepository(null));
	}

	@Test
	public void findRegistrationWhenRegistrationIsPresentThenReturns() {
		String id = this.registration.getRegistrationId();
		assertThat(this.registrationRepository.findByRegistrationId(id).block()).isEqualTo(this.registration);
	}

	@Test
	public void findRegistrationWhenRegistrationIsNotPresentThenNull() {
		String id = this.registration.getRegistrationId() + "MISSING";
		assertThat(this.registrationRepository.findByRegistrationId(id).block()).isNull();
	}

	@Test
	public void findRegistrationWhenNullIdIsPresentThenThrowsException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.registrationRepository.findByRegistrationId(null).block());
	}

	@Test
	public void findRegistrationWhenIdIsPresentThenSingletonSupplierCached() {
		given(this.clientRegistrationRepositorySupplier.get())
			.willReturn(new InMemoryReactiveClientRegistrationRepository(this.registration));
		SupplierReactiveClientRegistrationRepository test = new SupplierReactiveClientRegistrationRepository(
				this.clientRegistrationRepositorySupplier);

		String id = this.registration.getRegistrationId();
		assertThat(test.findByRegistrationId(id).block()).isEqualTo(this.registration);

		id = this.registration.getRegistrationId();
		assertThat(test.findByRegistrationId(id).block()).isEqualTo(this.registration);
		verify(this.clientRegistrationRepositorySupplier, times(1)).get();
	}

	@Test
	public void iteratorWhenRemoveThenThrowsUnsupportedOperationException() {
		assertThatExceptionOfType(UnsupportedOperationException.class)
			.isThrownBy(this.registrationRepository.iterator()::remove);
	}

	@Test
	public void iteratorWhenGetThenContainsAll() {
		assertThat(this.registrationRepository).containsOnly(this.registration);
	}

}
