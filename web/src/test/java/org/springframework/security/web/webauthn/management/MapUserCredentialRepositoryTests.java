/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.webauthn.management;

import java.time.Instant;

import org.junit.jupiter.api.Test;

import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.ImmutableCredentialRecord;
import org.springframework.security.web.webauthn.api.TestCredentialRecord;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNoException;

/**
 * Tests for {@link MapUserCredentialRepository}
 *
 * @author Rob Winch
 * @since 6.4
 */
class MapUserCredentialRepositoryTests {

	private final MapUserCredentialRepository userCredentials = new MapUserCredentialRepository();

	@Test
	void findByUserIdWhenNotFoundThenEmpty() {
		assertThat(this.userCredentials.findByUserId(Bytes.random())).isEmpty();
	}

	@Test
	void findByUserIdWhenNullIdThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.userCredentials.findByUserId(null));
	}

	@Test
	void findByCredentialIdWhenIdNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.userCredentials.findByCredentialId(null));
	}

	@Test
	void findByCredentialIdWhenNotFoundThenIllegalArgumentException() {
		assertThat(this.userCredentials.findByCredentialId(Bytes.random())).isNull();
	}

	@Test
	void deleteWhenCredentialNotFoundThenNoException() {
		ImmutableCredentialRecord credentialRecord = TestCredentialRecord.userCredential().build();
		assertThatNoException().isThrownBy(() -> this.userCredentials.delete(credentialRecord.getCredentialId()));
	}

	@Test
	void deleteWhenNullIdThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.userCredentials.delete(null));
	}

	@Test
	void saveThenFound() {
		ImmutableCredentialRecord credentialRecord = TestCredentialRecord.userCredential().build();
		this.userCredentials.save(credentialRecord);
		assertThat(this.userCredentials.findByCredentialId(credentialRecord.getCredentialId()))
			.isEqualTo(credentialRecord);
		assertThat(this.userCredentials.findByUserId(credentialRecord.getUserEntityUserId()))
			.containsOnly(credentialRecord);
	}

	@Test
	void saveWhenNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.userCredentials.save(null));
	}

	@Test
	void saveAndDeleteThenNotFound() {
		ImmutableCredentialRecord credentialRecord = TestCredentialRecord.userCredential().build();
		this.userCredentials.save(credentialRecord);
		this.userCredentials.delete(credentialRecord.getCredentialId());
		assertThat(this.userCredentials.findByCredentialId(credentialRecord.getCredentialId())).isNull();
		assertThat(this.userCredentials.findByUserId(credentialRecord.getUserEntityUserId())).isEmpty();
	}

	@Test
	void saveWhenUpdateThenUpdated() {
		ImmutableCredentialRecord credentialRecord = TestCredentialRecord.userCredential().build();
		this.userCredentials.save(credentialRecord);
		Instant updatedLastUsed = credentialRecord.getLastUsed().plusSeconds(120);
		CredentialRecord updatedCredentialRecord = ImmutableCredentialRecord.fromCredentialRecord(credentialRecord)
			.lastUsed(updatedLastUsed)
			.build();
		this.userCredentials.save(updatedCredentialRecord);
		assertThat(this.userCredentials.findByCredentialId(credentialRecord.getCredentialId()))
			.isEqualTo(updatedCredentialRecord);
		assertThat(this.userCredentials.findByUserId(credentialRecord.getUserEntityUserId()))
			.containsOnly(updatedCredentialRecord);
	}

	@Test
	void saveWhenSameUserThenUpdated() {
		ImmutableCredentialRecord credentialRecord = TestCredentialRecord.userCredential().build();
		this.userCredentials.save(credentialRecord);
		CredentialRecord newCredentialRecord = ImmutableCredentialRecord.fromCredentialRecord(credentialRecord)
			.credentialId(Bytes.random())
			.build();
		this.userCredentials.save(newCredentialRecord);
		assertThat(this.userCredentials.findByCredentialId(credentialRecord.getCredentialId()))
			.isEqualTo(credentialRecord);
		assertThat(this.userCredentials.findByCredentialId(newCredentialRecord.getCredentialId()))
			.isEqualTo(newCredentialRecord);
		assertThat(this.userCredentials.findByUserId(credentialRecord.getUserEntityUserId()))
			.containsOnly(credentialRecord, newCredentialRecord);
	}

	@Test
	void saveWhenDifferentUserThenNewEntryAdded() {
		ImmutableCredentialRecord credentialRecord = TestCredentialRecord.userCredential().build();
		this.userCredentials.save(credentialRecord);
		CredentialRecord newCredentialRecord = ImmutableCredentialRecord.fromCredentialRecord(credentialRecord)
			.userEntityUserId(Bytes.random())
			.credentialId(Bytes.random())
			.build();
		this.userCredentials.save(newCredentialRecord);
		assertThat(this.userCredentials.findByCredentialId(credentialRecord.getCredentialId()))
			.isEqualTo(credentialRecord);
		assertThat(this.userCredentials.findByCredentialId(newCredentialRecord.getCredentialId()))
			.isEqualTo(newCredentialRecord);
		assertThat(this.userCredentials.findByUserId(credentialRecord.getUserEntityUserId()))
			.containsOnly(credentialRecord);
		assertThat(this.userCredentials.findByUserId(newCredentialRecord.getUserEntityUserId()))
			.containsOnly(newCredentialRecord);
	}

}
