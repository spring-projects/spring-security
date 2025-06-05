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

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.serializer.DefaultSerializer;
import org.springframework.core.serializer.Serializer;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.saml2.core.Saml2X509Credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link JdbcAssertingPartyMetadataRepository}
 */
class JdbcAssertingPartyMetadataRepositoryTests {

	private static final String SCHEMA_SQL_RESOURCE = "org/springframework/security/saml2/saml2-asserting-party-metadata-schema.sql";

	private static final String SAVE_SQL = "INSERT INTO saml2_asserting_party_metadata ("
			+ JdbcAssertingPartyMetadataRepository.COLUMN_NAMES + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

	private static final String ENTITY_ID = "https://localhost/simplesaml/saml2/idp/metadata.php";

	private static final String SINGLE_SIGNON_URL = "https://localhost/SSO";

	private static final String SINGLE_SIGNON_BINDING = Saml2MessageBinding.REDIRECT.getUrn();

	private static final boolean SINGLE_SIGNON_SIGN_REQUEST = false;

	private static final String SINGLE_LOGOUT_URL = "https://localhost/SLO";

	private static final String SINGLE_LOGOUT_RESPONSE_URL = "https://localhost/SLO/response";

	private static final String SINGLE_LOGOUT_BINDING = Saml2MessageBinding.REDIRECT.getUrn();

	private static final List<String> SIGNING_ALGORITHMS = List.of("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");

	private X509Certificate certificate;

	private EmbeddedDatabase db;

	private JdbcAssertingPartyMetadataRepository repository;

	private JdbcOperations jdbcOperations;

	private final Serializer<Object> serializer = new DefaultSerializer();

	@BeforeEach
	void setUp() {
		this.db = createDb();
		this.jdbcOperations = new JdbcTemplate(this.db);
		this.repository = new JdbcAssertingPartyMetadataRepository(this.jdbcOperations);
		this.certificate = loadCertificate("rsa.crt");
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
	void findByEntityId() throws IOException {
		this.jdbcOperations.update(SAVE_SQL, ENTITY_ID, SINGLE_SIGNON_URL, SINGLE_SIGNON_BINDING,
				SINGLE_SIGNON_SIGN_REQUEST, this.serializer.serializeToByteArray(SIGNING_ALGORITHMS),
				this.serializer.serializeToByteArray(asCredentials(this.certificate)),
				this.serializer.serializeToByteArray(asCredentials(this.certificate)), SINGLE_LOGOUT_URL,
				SINGLE_LOGOUT_RESPONSE_URL, SINGLE_LOGOUT_BINDING);

		AssertingPartyMetadata found = this.repository.findByEntityId(ENTITY_ID);

		assertThat(found).isNotNull();
		assertThat(found.getEntityId()).isEqualTo(ENTITY_ID);
		assertThat(found.getSingleSignOnServiceLocation()).isEqualTo(SINGLE_SIGNON_URL);
		assertThat(found.getSingleSignOnServiceBinding().getUrn()).isEqualTo(SINGLE_SIGNON_BINDING);
		assertThat(found.getWantAuthnRequestsSigned()).isEqualTo(SINGLE_SIGNON_SIGN_REQUEST);
		assertThat(found.getSingleLogoutServiceLocation()).isEqualTo(SINGLE_LOGOUT_URL);
		assertThat(found.getSingleLogoutServiceResponseLocation()).isEqualTo(SINGLE_LOGOUT_RESPONSE_URL);
		assertThat(found.getSingleLogoutServiceBinding().getUrn()).isEqualTo(SINGLE_LOGOUT_BINDING);
		assertThat(found.getSigningAlgorithms()).contains(SIGNING_ALGORITHMS.get(0));
		assertThat(found.getVerificationX509Credentials()).hasSize(1);
		assertThat(found.getEncryptionX509Credentials()).hasSize(1);
	}

	@Test
	void findByEntityIdWhenNotExists() {
		AssertingPartyMetadata found = this.repository.findByEntityId("non-existent-entity-id");
		assertThat(found).isNull();
	}

	@Test
	void iterator() throws IOException {
		this.jdbcOperations.update(SAVE_SQL, ENTITY_ID, SINGLE_SIGNON_URL, SINGLE_SIGNON_BINDING,
				SINGLE_SIGNON_SIGN_REQUEST, this.serializer.serializeToByteArray(SIGNING_ALGORITHMS),
				this.serializer.serializeToByteArray(asCredentials(this.certificate)),
				this.serializer.serializeToByteArray(asCredentials(this.certificate)), SINGLE_LOGOUT_URL,
				SINGLE_LOGOUT_RESPONSE_URL, SINGLE_LOGOUT_BINDING);

		this.jdbcOperations.update(SAVE_SQL, "https://localhost/simplesaml2/saml2/idp/metadata.php", SINGLE_SIGNON_URL,
				SINGLE_SIGNON_BINDING, SINGLE_SIGNON_SIGN_REQUEST,
				this.serializer.serializeToByteArray(SIGNING_ALGORITHMS),
				this.serializer.serializeToByteArray(asCredentials(this.certificate)),
				this.serializer.serializeToByteArray(asCredentials(this.certificate)), SINGLE_LOGOUT_URL,
				SINGLE_LOGOUT_RESPONSE_URL, SINGLE_LOGOUT_BINDING);

		Iterator<AssertingPartyMetadata> iterator = this.repository.iterator();
		AssertingPartyMetadata first = iterator.next();
		assertThat(first).isNotNull();
		AssertingPartyMetadata second = iterator.next();
		assertThat(second).isNotNull();
		assertThat(iterator.hasNext()).isFalse();
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

	private X509Certificate loadCertificate(String path) {
		try (InputStream is = new ClassPathResource(path).getInputStream()) {
			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			return (X509Certificate) factory.generateCertificate(is);
		}
		catch (Exception ex) {
			throw new RuntimeException("Error loading certificate from " + path, ex);
		}
	}

	private Collection<Saml2X509Credential> asCredentials(X509Certificate certificate) {
		return List.of(new Saml2X509Credential(certificate, Saml2X509Credential.Saml2X509CredentialType.ENCRYPTION,
				Saml2X509Credential.Saml2X509CredentialType.VERIFICATION));
	}

}
