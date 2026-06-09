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

package org.springframework.security.saml2.provider.service.registration;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.ObjectOutputStream;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link JdbcAssertingPartyMetadataRepository} when Bouncy Castle is the
 * preferred JCA provider. Run in their own forked JVM (see the {@code bouncyCastleTest}
 * Gradle task) so that the production code's allowlist is computed with BC registered and
 * so this provider change does not leak into other tests.
 */
class JdbcAssertingPartyMetadataRepositoryBouncyCastleTests {

	private static final String SCHEMA_SQL_RESOURCE = "org/springframework/security/saml2/saml2-asserting-party-metadata-schema.sql";

	static {
		Security.insertProviderAt(new BouncyCastleProvider(), 1);
	}

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
	void findByEntityIdWhenEntityPresentThenReturns() {
		this.repository.save(this.metadata);

		AssertingPartyMetadata found = this.repository.findByEntityId(this.metadata.getEntityId());

		assertAssertingPartyEquals(found, this.metadata);
	}

	@Test
	void saveWhenExistingThenUpdates() {
		this.repository.save(this.metadata);
		boolean existing = this.metadata.getWantAuthnRequestsSigned();
		this.repository.save(this.metadata.mutate().wantAuthnRequestsSigned(!existing).build());
		boolean updated = this.repository.findByEntityId(this.metadata.getEntityId()).getWantAuthnRequestsSigned();
		assertThat(existing).isNotEqualTo(updated);
	}

	@Test
	void findByEntityIdWhenSerializedTypeNotInAllowlistThenFailsDeserialization() throws Exception {
		this.repository.save(this.metadata);
		byte[] notAllowed = serialize(new HashMap<>(Map.of("not", "allowed")));
		this.jdbcOperations.update(
				"UPDATE saml2_asserting_party_metadata SET verification_credentials = ? WHERE entity_id = ?",
				notAllowed, this.metadata.getEntityId());

		assertThatExceptionOfType(RuntimeException.class)
			.isThrownBy(() -> this.repository.findByEntityId(this.metadata.getEntityId()))
			.withRootCauseInstanceOf(InvalidClassException.class);
	}

	private static byte[] serialize(Object value) throws IOException {
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		try (ObjectOutputStream oos = new ObjectOutputStream(bytes)) {
			oos.writeObject(value);
		}
		return bytes.toByteArray();
	}

	private static EmbeddedDatabase createDb() {
		// @formatter:off
		return new EmbeddedDatabaseBuilder()
				.generateUniqueName(true)
				.setType(EmbeddedDatabaseType.HSQL)
				.setScriptEncoding("UTF-8")
				.addScript(SCHEMA_SQL_RESOURCE)
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
