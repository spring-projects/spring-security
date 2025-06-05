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

package org.springframework.security.saml2.provider.service.registration;

import java.util.Iterator;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link JdbcAssertingPartyMetadataRepository}
 */
class JdbcAssertingPartyMetadataRepositoryTests {

	private static final String SCHEMA_SQL_RESOURCE = "org/springframework/security/saml2/saml2-asserting-party-metadata-schema.sql";

	private EmbeddedDatabase db;

	private JdbcAssertingPartyMetadataRepository repository;

	private JdbcOperations jdbcOperations;

	private final AssertingPartyMetadata metadata = TestRelyingPartyRegistrations.full()
		.build()
		.getAssertingPartyMetadata();

	@BeforeEach
	void setUp() {
		this.db = createDb();
		this.jdbcOperations = new JdbcTemplate(this.db);
		this.repository = new JdbcAssertingPartyMetadataRepository(this.jdbcOperations);
	}

	@AfterEach
	void tearDown() {
		this.db.shutdown();
	}

	@Test
	void constructorWhenJdbcOperationsIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new JdbcAssertingPartyMetadataRepository(null))
				.withMessage("jdbcOperations cannot be null");
		// @formatter:on
	}

	@Test
	void findByEntityIdWhenEntityIdIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.repository.findByEntityId(null))
				.withMessage("entityId cannot be empty");
		// @formatter:on
	}

	@Test
	void findByEntityId() {
		this.repository.save(this.metadata);

		AssertingPartyMetadata found = this.repository.findByEntityId(this.metadata.getEntityId());

		assertAssertingPartyEquals(found, this.metadata);
	}

	@Test
	void findByEntityIdWhenNotExists() {
		AssertingPartyMetadata found = this.repository.findByEntityId("non-existent-entity-id");
		assertThat(found).isNull();
	}

	@Test
	void iterator() {
		AssertingPartyMetadata second = RelyingPartyRegistration.withAssertingPartyMetadata(this.metadata)
			.assertingPartyMetadata((a) -> a.entityId("https://example.org/idp"))
			.build()
			.getAssertingPartyMetadata();
		this.repository.save(this.metadata);
		this.repository.save(second);

		Iterator<AssertingPartyMetadata> iterator = this.repository.iterator();

		assertAssertingPartyEquals(iterator.next(), this.metadata);
		assertAssertingPartyEquals(iterator.next(), second);
		assertThat(iterator.hasNext()).isFalse();
	}

	@Test
	void saveWhenExistingThenUpdates() {
		this.repository.save(this.metadata);
		boolean existing = this.metadata.getWantAuthnRequestsSigned();
		this.repository.save(this.metadata.mutate().wantAuthnRequestsSigned(!existing).build());
		boolean updated = this.repository.findByEntityId(this.metadata.getEntityId()).getWantAuthnRequestsSigned();
		assertThat(existing).isNotEqualTo(updated);
	}

	private static EmbeddedDatabase createDb() {
		return createDb(SCHEMA_SQL_RESOURCE);
	}

	private static EmbeddedDatabase createDb(String schema) {
		// @formatter:off
		return new EmbeddedDatabaseBuilder()
				.generateUniqueName(true)
				.setType(EmbeddedDatabaseType.HSQL)
				.setScriptEncoding("UTF-8")
				.addScript(schema)
				.build();
		// @formatter:on
	}

	private void assertAssertingPartyEquals(AssertingPartyMetadata found, AssertingPartyMetadata expected) {
		assertThat(found).isNotNull();
		assertThat(found.getEntityId()).isEqualTo(expected.getEntityId());
		assertThat(found.getSingleSignOnServiceLocation()).isEqualTo(expected.getSingleSignOnServiceLocation());
		assertThat(found.getSingleSignOnServiceBinding()).isEqualTo(expected.getSingleSignOnServiceBinding());
		assertThat(found.getWantAuthnRequestsSigned()).isEqualTo(expected.getWantAuthnRequestsSigned());
		assertThat(found.getSingleLogoutServiceLocation()).isEqualTo(expected.getSingleLogoutServiceLocation());
		assertThat(found.getSingleLogoutServiceResponseLocation())
			.isEqualTo(expected.getSingleLogoutServiceResponseLocation());
		assertThat(found.getSingleLogoutServiceBinding()).isEqualTo(expected.getSingleLogoutServiceBinding());
		assertThat(found.getSigningAlgorithms()).containsAll(expected.getSigningAlgorithms());
		assertThat(found.getVerificationX509Credentials()).containsAll(expected.getVerificationX509Credentials());
		assertThat(found.getEncryptionX509Credentials()).containsAll(expected.getEncryptionX509Credentials());
	}

}
