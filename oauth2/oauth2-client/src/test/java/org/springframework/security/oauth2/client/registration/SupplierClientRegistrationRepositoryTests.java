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

package org.springframework.security.oauth2.client.registration;

import java.util.Collections;
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
 * Tests for {@link SupplierClientRegistrationRepository}.
 *
 * @author Justin Tay
 * @since 6.2
 */
@ExtendWith(MockitoExtension.class)
public class SupplierClientRegistrationRepositoryTests {

	private ClientRegistration registration = TestClientRegistrations.clientRegistration().build();

	private SupplierClientRegistrationRepository clients = new SupplierClientRegistrationRepository(
			() -> new InMemoryClientRegistrationRepository(this.registration));

	@Mock
	Supplier<InMemoryClientRegistrationRepository> clientRegistrationRepositorySupplier;

	@Test
	public void constructorMapClientRegistrationWhenNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new SupplierClientRegistrationRepository(null));
	}

	@Test
	public void constructorMapClientRegistrationWhenEmptyMapThenRepositoryIsEmpty() {
		SupplierClientRegistrationRepository clients = new SupplierClientRegistrationRepository(
				() -> new InMemoryClientRegistrationRepository(Collections.emptyMap()));
		assertThat(clients).isEmpty();
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

	@Test
	public void findByRegistrationIdWhenNullIdThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.clients.findByRegistrationId(null));
	}

	@Test
	public void findByRegistrationIdThenSingletonSupplierCached() {
		SupplierClientRegistrationRepository test = new SupplierClientRegistrationRepository(
				this.clientRegistrationRepositorySupplier);
		given(this.clientRegistrationRepositorySupplier.get())
			.willReturn(new InMemoryClientRegistrationRepository(this.registration));
		String id = this.registration.getRegistrationId();
		assertThat(test.findByRegistrationId(id)).isEqualTo(this.registration);
		id = this.registration.getRegistrationId();
		assertThat(test.findByRegistrationId(id)).isEqualTo(this.registration);
		verify(this.clientRegistrationRepositorySupplier, times(1)).get();
	}

	@Test
	public void iteratorWhenRemoveThenThrowsUnsupportedOperationException() {
		assertThatExceptionOfType(UnsupportedOperationException.class).isThrownBy(this.clients.iterator()::remove);
	}

	@Test
	public void iteratorWhenGetThenContainsAll() {
		assertThat(this.clients).containsOnly(this.registration);
	}

}
