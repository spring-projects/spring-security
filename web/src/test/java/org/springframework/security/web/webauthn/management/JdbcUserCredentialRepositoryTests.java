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

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.web.webauthn.api.AuthenticatorTransport;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;
import org.springframework.security.web.webauthn.api.TestCredentialRecord;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link JdbcUserCredentialRepository}
 *
 * @author Max Batischev
 */
public class JdbcUserCredentialRepositoryTests {

	private EmbeddedDatabase db;

	private JdbcUserCredentialRepository jdbcUserCredentialRepository;

	private static final String USER_CREDENTIALS_SQL_RESOURCE = "org/springframework/security/user-credentials-schema.sql";

	@BeforeEach
	void setUp() {
		this.db = createDb();
		JdbcOperations jdbcOperations = new JdbcTemplate(this.db);
		this.jdbcUserCredentialRepository = new JdbcUserCredentialRepository(jdbcOperations);
	}

	@AfterEach
	void tearDown() {
		this.db.shutdown();
	}

	private static EmbeddedDatabase createDb() {
		// @formatter:off
		return new EmbeddedDatabaseBuilder()
				.generateUniqueName(true)
				.setType(EmbeddedDatabaseType.HSQL)
				.setScriptEncoding("UTF-8")
				.addScript(USER_CREDENTIALS_SQL_RESOURCE)
				.build();
		// @formatter:on
	}

	@Test
	void constructorWhenJdbcOperationsIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new JdbcUserCredentialRepository(null))
				.withMessage("jdbcOperations cannot be null");
		// @formatter:on
	}

	@Test
	void saveWhenCredentialRecordIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.jdbcUserCredentialRepository.save(null))
				.withMessage("record cannot be null");
		// @formatter:on
	}

	@Test
	void findByCredentialIdWheCredentialIdIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.jdbcUserCredentialRepository.findByCredentialId(null))
				.withMessage("credentialId cannot be null");
		// @formatter:on
	}

	@Test
	void findByCredentialIdWheUserIdIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.jdbcUserCredentialRepository.findByUserId(null))
				.withMessage("userId cannot be null");
		// @formatter:on
	}

	@Test
	void saveCredentialRecordWhenSaveThenReturnsSaved() {
		CredentialRecord userCredential = TestCredentialRecord.fullUserCredential().build();
		this.jdbcUserCredentialRepository.save(userCredential);

		CredentialRecord savedUserCredential = this.jdbcUserCredentialRepository
			.findByCredentialId(userCredential.getCredentialId());

		assertThat(savedUserCredential).isNotNull();
		assertThat(savedUserCredential.getCredentialId()).isEqualTo(userCredential.getCredentialId());
		assertThat(savedUserCredential.getUserEntityUserId()).isEqualTo(userCredential.getUserEntityUserId());
		assertThat(savedUserCredential.getLabel()).isEqualTo(userCredential.getLabel());
		assertThat(savedUserCredential.getPublicKey().getBytes()).isEqualTo(userCredential.getPublicKey().getBytes());
		assertThat(savedUserCredential.isBackupEligible()).isEqualTo(userCredential.isBackupEligible());
		assertThat(savedUserCredential.isBackupState()).isEqualTo(userCredential.isBackupState());
		assertThat(savedUserCredential.getCreated()).isNotNull();
		assertThat(savedUserCredential.getLastUsed()).isNotNull();
		assertThat(savedUserCredential.isUvInitialized()).isFalse();
		assertThat(savedUserCredential.getSignatureCount()).isEqualTo(100);
		assertThat(savedUserCredential.getCredentialType()).isEqualTo(PublicKeyCredentialType.PUBLIC_KEY);
		assertThat(savedUserCredential.getTransports().contains(AuthenticatorTransport.HYBRID)).isTrue();
		assertThat(savedUserCredential.getTransports().contains(AuthenticatorTransport.BLE)).isTrue();
		assertThat(new String(savedUserCredential.getAttestationObject().getBytes())).isEqualTo("test");
		assertThat(new String(savedUserCredential.getAttestationClientDataJSON().getBytes())).isEqualTo("test");
	}

	@Test
	void findCredentialRecordByUserIdWhenRecordExistsThenReturnsSaved() {
		CredentialRecord userCredential = TestCredentialRecord.fullUserCredential().build();
		this.jdbcUserCredentialRepository.save(userCredential);

		List<CredentialRecord> credentialRecords = this.jdbcUserCredentialRepository
			.findByUserId(userCredential.getUserEntityUserId());

		assertThat(credentialRecords).isNotNull();
		assertThat(credentialRecords.size()).isEqualTo(1);
	}

	@Test
	void findCredentialRecordByUserIdWhenRecordDoesNotExistThenReturnsEmpty() {
		CredentialRecord userCredential = TestCredentialRecord.fullUserCredential().build();

		List<CredentialRecord> credentialRecords = this.jdbcUserCredentialRepository
			.findByUserId(userCredential.getUserEntityUserId());

		assertThat(credentialRecords.size()).isEqualTo(0);
	}

	@Test
	void findCredentialRecordByCredentialIdWhenRecordDoesNotExistThenReturnsNull() {
		CredentialRecord userCredential = TestCredentialRecord.fullUserCredential().build();

		CredentialRecord credentialRecord = this.jdbcUserCredentialRepository
			.findByCredentialId(userCredential.getCredentialId());

		assertThat(credentialRecord).isNull();
	}

	@Test
	void deleteCredentialRecordWhenRecordExistThenSuccess() {
		CredentialRecord userCredential = TestCredentialRecord.fullUserCredential().build();
		this.jdbcUserCredentialRepository.save(userCredential);

		this.jdbcUserCredentialRepository.delete(userCredential.getCredentialId());

		CredentialRecord credentialRecord = this.jdbcUserCredentialRepository
			.findByCredentialId(userCredential.getCredentialId());
		assertThat(credentialRecord).isNull();
	}

}
