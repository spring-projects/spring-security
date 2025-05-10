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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.converter.RsaKeyConverters;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link JdbcRelyingPartyRegistrationRepository}
 */
public class JdbcRelyingPartyRegistrationRepositoryTests {

	private static final String RP_REGISTRATION_SCHEMA_SQL_RESOURCE = "org/springframework/security/saml2/saml2-relying-party-registration-schema.sql";

	private static final String SAVE_RP_REGISTRATION_SQL = "INSERT INTO saml2_relying_party_registration" + " ("
			+ JdbcRelyingPartyRegistrationRepository.COLUMN_NAMES
			+ ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

	private static final String REGISTRATION_ID = "adfs";

	private static final String ENTITY_ID = "https://rp.example.org/saml2/service-provider-metadata/adfs";

	private static final String NAME_ID_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

	private static final String ACS_LOCATION = "https://rp.example.org/login/saml2/sso/adfs";

	private static final String ACS_BINDING = Saml2MessageBinding.POST.getUrn();

	private static final String SINGLE_LOGOUT_URL = "https://rp.example.org/logout/saml2/slo";

	private static final String SINGLE_LOGOUT_RESPONSE_URL = "https://rp.example.org/logout/saml2/slo";

	private static final String SINGLE_LOGOUT_BINDING = Saml2MessageBinding.POST.getUrn();

	private static final String ASSERTINGPARTY_ENTITY_ID = "https://localhost/simplesaml/saml2/idp/metadata.php";

	private static final String ASSERTINGPARTY_SINGLE_SIGNON_URL = "https://localhost/SSO";

	private static final String ASSERTINGPARTY_SINGLE_SIGNON_BINDING = Saml2MessageBinding.REDIRECT.getUrn();

	private static final String ASSERTINGPARTY_SINGLE_SIGNON_SIGN_REQUEST = "true";

	private static final String ASSERTINGPARTY_SINGLE_LOGOUT_URL = "https://localhost/SLO";

	private static final String ASSERTINGPARTY_SINGLE_LOGOUT_RESPONSE_URL = "https://localhost/SLO/response";

	private static final String ASSERTINGPARTY_SINGLE_LOGOUT_BINDING = Saml2MessageBinding.REDIRECT.getUrn();

	private String assertingpartyMetadataUri;

	private String signingCredentials;

	private String decryptionCredentials;

	private String assertingpartyVerificationCredentials;

	private EmbeddedDatabase db;

	private JdbcRelyingPartyRegistrationRepository repository;

	private JdbcOperations jdbcOperations;

	private final ObjectMapper objectMapper = new ObjectMapper();

	private final MockWebServer mockWebServer = new MockWebServer();

	@BeforeEach
	public void setUp() throws Exception {
		this.db = createDb();
		this.jdbcOperations = new JdbcTemplate(this.db);
		this.repository = new JdbcRelyingPartyRegistrationRepository(this.jdbcOperations);

		ClassPathResource resource = new ClassPathResource("test-federated-metadata.xml");
		String metadata;
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(resource.getInputStream()))) {
			metadata = reader.lines().collect(Collectors.joining());
		}

		this.mockWebServer.enqueue(new MockResponse().setBody(metadata).setResponseCode(200));
		this.assertingpartyMetadataUri = this.mockWebServer.url("/metadata").toString();

		X509Certificate x509Certificate = loadCertificate("rsa.crt");
		RSAPrivateKey rsaPrivateKey = loadPrivateKey("rsa.key");
		String credentials = this.objectMapper
			.writeValueAsString(List.of(new JdbcRelyingPartyRegistrationRepository.Credential(
					Base64.getEncoder().encodeToString(rsaPrivateKey.getEncoded()),
					Base64.getEncoder().encodeToString(x509Certificate.getEncoded()))));
		this.signingCredentials = credentials;
		this.decryptionCredentials = credentials;
		this.assertingpartyVerificationCredentials = this.objectMapper
			.writeValueAsString(List.of(new JdbcRelyingPartyRegistrationRepository.Certificate(
					Base64.getEncoder().encodeToString(x509Certificate.getEncoded()))));
	}

	@AfterEach
	public void tearDown() throws IOException {
		this.db.shutdown();
		this.mockWebServer.close();
	}

	@Test
	void constructorWhenJdbcOperationsIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new JdbcRelyingPartyRegistrationRepository(null))
				.withMessage("jdbcOperations cannot be null");
		// @formatter:on
	}

	@Test
	void findByRegistrationIdWhenCredentialIdIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.repository.findByRegistrationId(null))
				.withMessage("registrationId cannot be empty");
		// @formatter:on
	}

	@Test
	void findByRegistrationIdWhenAssertingpartyMetadataUriIsNull() {
		this.jdbcOperations.update(SAVE_RP_REGISTRATION_SQL, REGISTRATION_ID, ENTITY_ID, NAME_ID_FORMAT, ACS_LOCATION,
				ACS_BINDING, this.signingCredentials.getBytes(StandardCharsets.UTF_8),
				this.decryptionCredentials.getBytes(StandardCharsets.UTF_8), SINGLE_LOGOUT_URL,
				SINGLE_LOGOUT_RESPONSE_URL, SINGLE_LOGOUT_BINDING, ASSERTINGPARTY_ENTITY_ID, null,
				ASSERTINGPARTY_SINGLE_SIGNON_URL, ASSERTINGPARTY_SINGLE_SIGNON_BINDING,
				ASSERTINGPARTY_SINGLE_SIGNON_SIGN_REQUEST,
				this.assertingpartyVerificationCredentials.getBytes(StandardCharsets.UTF_8),
				ASSERTINGPARTY_SINGLE_LOGOUT_URL, ASSERTINGPARTY_SINGLE_LOGOUT_RESPONSE_URL,
				ASSERTINGPARTY_SINGLE_LOGOUT_BINDING);

		RelyingPartyRegistration result = this.repository.findByRegistrationId(REGISTRATION_ID);

		assertThat(result).isNotNull();
		assertThat(result.getRegistrationId()).isEqualTo(REGISTRATION_ID);
		assertThat(result.getEntityId()).isEqualTo(ENTITY_ID);
		assertThat(result.getNameIdFormat()).isEqualTo(NAME_ID_FORMAT);
		assertThat(result.getAssertionConsumerServiceLocation()).isEqualTo(ACS_LOCATION);
		assertThat(result.getAssertionConsumerServiceBinding()).isEqualTo(Saml2MessageBinding.from(ACS_BINDING));
		assertThat(result.getSingleLogoutServiceLocation()).isEqualTo(SINGLE_LOGOUT_URL);
		assertThat(result.getSingleLogoutServiceResponseLocation()).isEqualTo(SINGLE_LOGOUT_RESPONSE_URL);
		assertThat(result.getSingleLogoutServiceBinding()).isEqualTo(Saml2MessageBinding.from(SINGLE_LOGOUT_BINDING));
		assertThat(result.getSigningX509Credentials()).hasSize(1);
		assertThat(result.getDecryptionX509Credentials()).hasSize(1);
		AssertingPartyMetadata apm = result.getAssertingPartyMetadata();
		assertThat(apm.getEntityId()).isEqualTo(ASSERTINGPARTY_ENTITY_ID);
		assertThat(apm.getSingleSignOnServiceLocation()).isEqualTo(ASSERTINGPARTY_SINGLE_SIGNON_URL);
		assertThat(apm.getSingleSignOnServiceBinding())
			.isEqualTo(Saml2MessageBinding.from(ASSERTINGPARTY_SINGLE_SIGNON_BINDING));
		assertThat(apm.getWantAuthnRequestsSigned()).isTrue();
		assertThat(apm.getVerificationX509Credentials()).hasSize(1);
		assertThat(apm.getSingleLogoutServiceLocation()).isEqualTo(ASSERTINGPARTY_SINGLE_LOGOUT_URL);
		assertThat(apm.getSingleLogoutServiceResponseLocation()).isEqualTo(ASSERTINGPARTY_SINGLE_LOGOUT_RESPONSE_URL);
		assertThat(apm.getSingleLogoutServiceBinding())
			.isEqualTo(Saml2MessageBinding.from(ASSERTINGPARTY_SINGLE_LOGOUT_BINDING));
	}

	@Test
	void findByRegistrationIdWhenAssertingpartyMetadataUriExists() {
		this.jdbcOperations.update(SAVE_RP_REGISTRATION_SQL, REGISTRATION_ID, ENTITY_ID, NAME_ID_FORMAT, ACS_LOCATION,
				ACS_BINDING, this.signingCredentials.getBytes(StandardCharsets.UTF_8),
				this.decryptionCredentials.getBytes(StandardCharsets.UTF_8), SINGLE_LOGOUT_URL,
				SINGLE_LOGOUT_RESPONSE_URL, SINGLE_LOGOUT_BINDING, ASSERTINGPARTY_ENTITY_ID,
				this.assertingpartyMetadataUri, null, null, null, null, null, null, null);

		RelyingPartyRegistration result = this.repository.findByRegistrationId(REGISTRATION_ID);

		assertThat(result).isNotNull();
		assertThat(result.getRegistrationId()).isEqualTo(REGISTRATION_ID);
		assertThat(result.getEntityId()).isEqualTo(ENTITY_ID);
		assertThat(result.getNameIdFormat()).isEqualTo(NAME_ID_FORMAT);
		assertThat(result.getAssertionConsumerServiceLocation()).isEqualTo(ACS_LOCATION);
		assertThat(result.getAssertionConsumerServiceBinding()).isEqualTo(Saml2MessageBinding.from(ACS_BINDING));
		assertThat(result.getSingleLogoutServiceLocation()).isEqualTo(SINGLE_LOGOUT_URL);
		assertThat(result.getSingleLogoutServiceResponseLocation()).isEqualTo(SINGLE_LOGOUT_RESPONSE_URL);
		assertThat(result.getSingleLogoutServiceBinding()).isEqualTo(Saml2MessageBinding.from(SINGLE_LOGOUT_BINDING));
		assertThat(result.getSigningX509Credentials()).hasSize(1);
		assertThat(result.getDecryptionX509Credentials()).hasSize(1);
		AssertingPartyMetadata apm = result.getAssertingPartyMetadata();
		assertThat(apm.getEntityId()).isEqualTo(ASSERTINGPARTY_ENTITY_ID);
		assertThat(apm.getSingleSignOnServiceLocation())
			.isEqualTo("https://localhost/simplesaml/saml2/idp/SSOService.php");
		assertThat(apm.getSingleSignOnServiceBinding()).isEqualTo(Saml2MessageBinding.REDIRECT);
		assertThat(apm.getWantAuthnRequestsSigned()).isFalse();
		assertThat(apm.getVerificationX509Credentials()).hasSize(1);
		assertThat(apm.getSingleLogoutServiceLocation())
			.isEqualTo("https://localhost/simplesaml/saml2/idp/SingleLogoutService.php");
		assertThat(apm.getSingleLogoutServiceResponseLocation())
			.isEqualTo("https://localhost/simplesaml/saml2/idp/SingleLogoutService.php");
		assertThat(apm.getSingleLogoutServiceBinding()).isEqualTo(Saml2MessageBinding.REDIRECT);
	}

	@Test
	void findByRegistrationIdWhenAssertingpartyMetadataUriExistsAndAssertingpartyMetadataExists() {
		this.jdbcOperations.update(SAVE_RP_REGISTRATION_SQL, REGISTRATION_ID, ENTITY_ID, NAME_ID_FORMAT, ACS_LOCATION,
				ACS_BINDING, this.signingCredentials.getBytes(StandardCharsets.UTF_8),
				this.decryptionCredentials.getBytes(StandardCharsets.UTF_8), SINGLE_LOGOUT_URL,
				SINGLE_LOGOUT_RESPONSE_URL, SINGLE_LOGOUT_BINDING, ASSERTINGPARTY_ENTITY_ID,
				this.assertingpartyMetadataUri, ASSERTINGPARTY_SINGLE_SIGNON_URL, ASSERTINGPARTY_SINGLE_SIGNON_BINDING,
				ASSERTINGPARTY_SINGLE_SIGNON_SIGN_REQUEST,
				this.assertingpartyVerificationCredentials.getBytes(StandardCharsets.UTF_8),
				ASSERTINGPARTY_SINGLE_LOGOUT_URL, ASSERTINGPARTY_SINGLE_LOGOUT_RESPONSE_URL,
				ASSERTINGPARTY_SINGLE_LOGOUT_BINDING);

		RelyingPartyRegistration result = this.repository.findByRegistrationId(REGISTRATION_ID);

		assertThat(result).isNotNull();
		assertThat(result.getRegistrationId()).isEqualTo(REGISTRATION_ID);
		assertThat(result.getEntityId()).isEqualTo(ENTITY_ID);
		assertThat(result.getNameIdFormat()).isEqualTo(NAME_ID_FORMAT);
		assertThat(result.getAssertionConsumerServiceLocation()).isEqualTo(ACS_LOCATION);
		assertThat(result.getAssertionConsumerServiceBinding()).isEqualTo(Saml2MessageBinding.from(ACS_BINDING));
		assertThat(result.getSingleLogoutServiceLocation()).isEqualTo(SINGLE_LOGOUT_URL);
		assertThat(result.getSingleLogoutServiceResponseLocation()).isEqualTo(SINGLE_LOGOUT_RESPONSE_URL);
		assertThat(result.getSingleLogoutServiceBinding()).isEqualTo(Saml2MessageBinding.from(SINGLE_LOGOUT_BINDING));
		assertThat(result.getSigningX509Credentials()).hasSize(1);
		assertThat(result.getDecryptionX509Credentials()).hasSize(1);
		AssertingPartyMetadata apm = result.getAssertingPartyMetadata();
		assertThat(apm.getEntityId()).isEqualTo(ASSERTINGPARTY_ENTITY_ID);
		assertThat(apm.getSingleSignOnServiceLocation()).isEqualTo(ASSERTINGPARTY_SINGLE_SIGNON_URL);
		assertThat(apm.getSingleSignOnServiceBinding())
			.isEqualTo(Saml2MessageBinding.from(ASSERTINGPARTY_SINGLE_SIGNON_BINDING));
		assertThat(apm.getWantAuthnRequestsSigned()).isTrue();
		assertThat(apm.getVerificationX509Credentials()).hasSize(2);
		assertThat(apm.getSingleLogoutServiceLocation()).isEqualTo(ASSERTINGPARTY_SINGLE_LOGOUT_URL);
		assertThat(apm.getSingleLogoutServiceResponseLocation()).isEqualTo(ASSERTINGPARTY_SINGLE_LOGOUT_RESPONSE_URL);
		assertThat(apm.getSingleLogoutServiceBinding())
			.isEqualTo(Saml2MessageBinding.from(ASSERTINGPARTY_SINGLE_LOGOUT_BINDING));
	}

	@Test
	void findByRegistrationIdWhenMissingEntityIdAndAcsLocationAndAcsBinding() {
		this.jdbcOperations.update(SAVE_RP_REGISTRATION_SQL, REGISTRATION_ID, null, NAME_ID_FORMAT, null, null,
				this.signingCredentials.getBytes(StandardCharsets.UTF_8),
				this.decryptionCredentials.getBytes(StandardCharsets.UTF_8), SINGLE_LOGOUT_URL,
				SINGLE_LOGOUT_RESPONSE_URL, SINGLE_LOGOUT_BINDING, ASSERTINGPARTY_ENTITY_ID, null,
				ASSERTINGPARTY_SINGLE_SIGNON_URL, ASSERTINGPARTY_SINGLE_SIGNON_BINDING,
				ASSERTINGPARTY_SINGLE_SIGNON_SIGN_REQUEST,
				this.assertingpartyVerificationCredentials.getBytes(StandardCharsets.UTF_8),
				ASSERTINGPARTY_SINGLE_LOGOUT_URL, ASSERTINGPARTY_SINGLE_LOGOUT_RESPONSE_URL,
				ASSERTINGPARTY_SINGLE_LOGOUT_BINDING);

		RelyingPartyRegistration result = this.repository.findByRegistrationId(REGISTRATION_ID);

		assertThat(result).isNotNull();
		assertThat(result.getRegistrationId()).isEqualTo(REGISTRATION_ID);
		assertThat(result.getEntityId()).isEqualTo("{baseUrl}/saml2/service-provider-metadata/{registrationId}");
		assertThat(result.getNameIdFormat()).isEqualTo(NAME_ID_FORMAT);
		assertThat(result.getAssertionConsumerServiceLocation())
			.isEqualTo("{baseUrl}/login/saml2/sso/{registrationId}");
		assertThat(result.getAssertionConsumerServiceBinding()).isEqualTo(Saml2MessageBinding.POST);
		assertThat(result.getSingleLogoutServiceLocation()).isEqualTo(SINGLE_LOGOUT_URL);
		assertThat(result.getSingleLogoutServiceResponseLocation()).isEqualTo(SINGLE_LOGOUT_RESPONSE_URL);
		assertThat(result.getSingleLogoutServiceBinding()).isEqualTo(Saml2MessageBinding.from(SINGLE_LOGOUT_BINDING));
		assertThat(result.getSigningX509Credentials()).hasSize(1);
		assertThat(result.getDecryptionX509Credentials()).hasSize(1);
		AssertingPartyMetadata apm = result.getAssertingPartyMetadata();
		assertThat(apm.getEntityId()).isEqualTo(ASSERTINGPARTY_ENTITY_ID);
		assertThat(apm.getSingleSignOnServiceLocation()).isEqualTo(ASSERTINGPARTY_SINGLE_SIGNON_URL);
		assertThat(apm.getSingleSignOnServiceBinding())
			.isEqualTo(Saml2MessageBinding.from(ASSERTINGPARTY_SINGLE_SIGNON_BINDING));
		assertThat(apm.getWantAuthnRequestsSigned()).isTrue();
		assertThat(apm.getVerificationX509Credentials()).hasSize(1);
		assertThat(apm.getSingleLogoutServiceLocation()).isEqualTo(ASSERTINGPARTY_SINGLE_LOGOUT_URL);
		assertThat(apm.getSingleLogoutServiceResponseLocation()).isEqualTo(ASSERTINGPARTY_SINGLE_LOGOUT_RESPONSE_URL);
		assertThat(apm.getSingleLogoutServiceBinding())
			.isEqualTo(Saml2MessageBinding.from(ASSERTINGPARTY_SINGLE_LOGOUT_BINDING));
	}

	@Test
	void findByRegistrationIdWhenWantAuthnRequestsSignedButMissingSigningCredentials() {
		this.jdbcOperations.update(SAVE_RP_REGISTRATION_SQL, REGISTRATION_ID, ENTITY_ID, NAME_ID_FORMAT, ACS_LOCATION,
				ACS_BINDING, null, this.decryptionCredentials.getBytes(StandardCharsets.UTF_8), SINGLE_LOGOUT_URL,
				SINGLE_LOGOUT_RESPONSE_URL, SINGLE_LOGOUT_BINDING, ASSERTINGPARTY_ENTITY_ID, null,
				ASSERTINGPARTY_SINGLE_SIGNON_URL, ASSERTINGPARTY_SINGLE_SIGNON_BINDING,
				ASSERTINGPARTY_SINGLE_SIGNON_SIGN_REQUEST,
				this.assertingpartyVerificationCredentials.getBytes(StandardCharsets.UTF_8),
				ASSERTINGPARTY_SINGLE_LOGOUT_URL, ASSERTINGPARTY_SINGLE_LOGOUT_RESPONSE_URL,
				ASSERTINGPARTY_SINGLE_LOGOUT_BINDING);

		RelyingPartyRegistration result = this.repository.findByRegistrationId(REGISTRATION_ID);
		assertThat(result).isNull();
	}

	@Test
	void findByRegistrationIdWhenSigningCredentialsWithNonPrivateKey() throws JsonProcessingException {
		String invalidCredentials = this.objectMapper
			.writeValueAsString(List.of(new JdbcRelyingPartyRegistrationRepository.Credential(null, "")));
		this.jdbcOperations.update(SAVE_RP_REGISTRATION_SQL, REGISTRATION_ID, ENTITY_ID, NAME_ID_FORMAT, ACS_LOCATION,
				ACS_BINDING, invalidCredentials.getBytes(StandardCharsets.UTF_8),
				this.decryptionCredentials.getBytes(StandardCharsets.UTF_8), SINGLE_LOGOUT_URL,
				SINGLE_LOGOUT_RESPONSE_URL, SINGLE_LOGOUT_BINDING, ASSERTINGPARTY_ENTITY_ID, null,
				ASSERTINGPARTY_SINGLE_SIGNON_URL, ASSERTINGPARTY_SINGLE_SIGNON_BINDING,
				ASSERTINGPARTY_SINGLE_SIGNON_SIGN_REQUEST,
				this.assertingpartyVerificationCredentials.getBytes(StandardCharsets.UTF_8),
				ASSERTINGPARTY_SINGLE_LOGOUT_URL, ASSERTINGPARTY_SINGLE_LOGOUT_RESPONSE_URL,
				ASSERTINGPARTY_SINGLE_LOGOUT_BINDING);

		RelyingPartyRegistration result = this.repository.findByRegistrationId(REGISTRATION_ID);
		assertThat(result).isNull();
	}

	@Test
	void findByRegistrationIdWhenSigningCredentialsIsInvalid() throws JsonProcessingException {
		String invalidCredentials = this.objectMapper
			.writeValueAsString(List.of(new JdbcRelyingPartyRegistrationRepository.Credential("invalid", "invalid")));
		this.jdbcOperations.update(SAVE_RP_REGISTRATION_SQL, REGISTRATION_ID, ENTITY_ID, NAME_ID_FORMAT, ACS_LOCATION,
				ACS_BINDING, invalidCredentials.getBytes(StandardCharsets.UTF_8),
				this.decryptionCredentials.getBytes(StandardCharsets.UTF_8), SINGLE_LOGOUT_URL,
				SINGLE_LOGOUT_RESPONSE_URL, SINGLE_LOGOUT_BINDING, ASSERTINGPARTY_ENTITY_ID, null,
				ASSERTINGPARTY_SINGLE_SIGNON_URL, ASSERTINGPARTY_SINGLE_SIGNON_BINDING,
				ASSERTINGPARTY_SINGLE_SIGNON_SIGN_REQUEST,
				this.assertingpartyVerificationCredentials.getBytes(StandardCharsets.UTF_8),
				ASSERTINGPARTY_SINGLE_LOGOUT_URL, ASSERTINGPARTY_SINGLE_LOGOUT_RESPONSE_URL,
				ASSERTINGPARTY_SINGLE_LOGOUT_BINDING);

		RelyingPartyRegistration result = this.repository.findByRegistrationId(REGISTRATION_ID);
		assertThat(result).isNull();
	}

	@Test
	void findByRegistrationIdWhenDecryptionCredentialsIsInvalid() throws JsonProcessingException {
		String invalidCredentials = this.objectMapper
			.writeValueAsString(List.of(new JdbcRelyingPartyRegistrationRepository.Credential("invalid", "invalid")));
		this.jdbcOperations.update(SAVE_RP_REGISTRATION_SQL, REGISTRATION_ID, ENTITY_ID, NAME_ID_FORMAT, ACS_LOCATION,
				ACS_BINDING, this.signingCredentials.getBytes(StandardCharsets.UTF_8),
				invalidCredentials.getBytes(StandardCharsets.UTF_8), SINGLE_LOGOUT_URL, SINGLE_LOGOUT_RESPONSE_URL,
				SINGLE_LOGOUT_BINDING, ASSERTINGPARTY_ENTITY_ID, null, ASSERTINGPARTY_SINGLE_SIGNON_URL,
				ASSERTINGPARTY_SINGLE_SIGNON_BINDING, ASSERTINGPARTY_SINGLE_SIGNON_SIGN_REQUEST,
				this.assertingpartyVerificationCredentials.getBytes(StandardCharsets.UTF_8),
				ASSERTINGPARTY_SINGLE_LOGOUT_URL, ASSERTINGPARTY_SINGLE_LOGOUT_RESPONSE_URL,
				ASSERTINGPARTY_SINGLE_LOGOUT_BINDING);

		RelyingPartyRegistration result = this.repository.findByRegistrationId(REGISTRATION_ID);
		assertThat(result).isNull();
	}

	@Test
	void findByRegistrationIdWhenVerificationCredentialsIsInvalid() throws JsonProcessingException {
		byte[] invalidVerificationCredential = this.signingCredentials.getBytes(StandardCharsets.UTF_8);
		this.jdbcOperations.update(SAVE_RP_REGISTRATION_SQL, REGISTRATION_ID, ENTITY_ID, NAME_ID_FORMAT, ACS_LOCATION,
				ACS_BINDING, this.signingCredentials.getBytes(StandardCharsets.UTF_8),
				this.decryptionCredentials.getBytes(StandardCharsets.UTF_8), SINGLE_LOGOUT_URL,
				SINGLE_LOGOUT_RESPONSE_URL, SINGLE_LOGOUT_BINDING, ASSERTINGPARTY_ENTITY_ID, null,
				ASSERTINGPARTY_SINGLE_SIGNON_URL, ASSERTINGPARTY_SINGLE_SIGNON_BINDING,
				ASSERTINGPARTY_SINGLE_SIGNON_SIGN_REQUEST, invalidVerificationCredential,
				ASSERTINGPARTY_SINGLE_LOGOUT_URL, ASSERTINGPARTY_SINGLE_LOGOUT_RESPONSE_URL,
				ASSERTINGPARTY_SINGLE_LOGOUT_BINDING);

		RelyingPartyRegistration result = this.repository.findByRegistrationId(REGISTRATION_ID);
		assertThat(result).isNull();
	}

	@Test
	void findByEntityId() {
		this.jdbcOperations.update(SAVE_RP_REGISTRATION_SQL, REGISTRATION_ID, ENTITY_ID, NAME_ID_FORMAT, ACS_LOCATION,
				ACS_BINDING, this.signingCredentials.getBytes(StandardCharsets.UTF_8),
				this.decryptionCredentials.getBytes(StandardCharsets.UTF_8), SINGLE_LOGOUT_URL,
				SINGLE_LOGOUT_RESPONSE_URL, SINGLE_LOGOUT_BINDING, ASSERTINGPARTY_ENTITY_ID, null,
				ASSERTINGPARTY_SINGLE_SIGNON_URL, ASSERTINGPARTY_SINGLE_SIGNON_BINDING,
				ASSERTINGPARTY_SINGLE_SIGNON_SIGN_REQUEST,
				this.assertingpartyVerificationCredentials.getBytes(StandardCharsets.UTF_8),
				ASSERTINGPARTY_SINGLE_LOGOUT_URL, ASSERTINGPARTY_SINGLE_LOGOUT_RESPONSE_URL,
				ASSERTINGPARTY_SINGLE_LOGOUT_BINDING);

		RelyingPartyRegistration result = this.repository.findUniqueByAssertingPartyEntityId(ENTITY_ID);

		assertThat(result).isNotNull();
		assertThat(result.getRegistrationId()).isEqualTo(REGISTRATION_ID);
		assertThat(result.getEntityId()).isEqualTo(ENTITY_ID);
		assertThat(result.getNameIdFormat()).isEqualTo(NAME_ID_FORMAT);
		assertThat(result.getAssertionConsumerServiceLocation()).isEqualTo(ACS_LOCATION);
		assertThat(result.getAssertionConsumerServiceBinding()).isEqualTo(Saml2MessageBinding.from(ACS_BINDING));
		assertThat(result.getSingleLogoutServiceLocation()).isEqualTo(SINGLE_LOGOUT_URL);
		assertThat(result.getSingleLogoutServiceResponseLocation()).isEqualTo(SINGLE_LOGOUT_RESPONSE_URL);
		assertThat(result.getSingleLogoutServiceBinding()).isEqualTo(Saml2MessageBinding.from(SINGLE_LOGOUT_BINDING));
		assertThat(result.getSigningX509Credentials()).hasSize(1);
		assertThat(result.getDecryptionX509Credentials()).hasSize(1);
		AssertingPartyMetadata apm = result.getAssertingPartyMetadata();
		assertThat(apm.getEntityId()).isEqualTo(ASSERTINGPARTY_ENTITY_ID);
		assertThat(apm.getSingleSignOnServiceLocation()).isEqualTo(ASSERTINGPARTY_SINGLE_SIGNON_URL);
		assertThat(apm.getSingleSignOnServiceBinding())
			.isEqualTo(Saml2MessageBinding.from(ASSERTINGPARTY_SINGLE_SIGNON_BINDING));
		assertThat(apm.getWantAuthnRequestsSigned()).isTrue();
		assertThat(apm.getVerificationX509Credentials()).hasSize(1);
		assertThat(apm.getSingleLogoutServiceLocation()).isEqualTo(ASSERTINGPARTY_SINGLE_LOGOUT_URL);
		assertThat(apm.getSingleLogoutServiceResponseLocation()).isEqualTo(ASSERTINGPARTY_SINGLE_LOGOUT_RESPONSE_URL);
		assertThat(apm.getSingleLogoutServiceBinding())
			.isEqualTo(Saml2MessageBinding.from(ASSERTINGPARTY_SINGLE_LOGOUT_BINDING));
	}

	@Test
	void iterator() {
		this.jdbcOperations.update(SAVE_RP_REGISTRATION_SQL, REGISTRATION_ID, ENTITY_ID, NAME_ID_FORMAT, ACS_LOCATION,
				ACS_BINDING, this.signingCredentials.getBytes(StandardCharsets.UTF_8),
				this.decryptionCredentials.getBytes(StandardCharsets.UTF_8), SINGLE_LOGOUT_URL,
				SINGLE_LOGOUT_RESPONSE_URL, SINGLE_LOGOUT_BINDING, ASSERTINGPARTY_ENTITY_ID, null,
				ASSERTINGPARTY_SINGLE_SIGNON_URL, ASSERTINGPARTY_SINGLE_SIGNON_BINDING,
				ASSERTINGPARTY_SINGLE_SIGNON_SIGN_REQUEST,
				this.assertingpartyVerificationCredentials.getBytes(StandardCharsets.UTF_8),
				ASSERTINGPARTY_SINGLE_LOGOUT_URL, ASSERTINGPARTY_SINGLE_LOGOUT_RESPONSE_URL,
				ASSERTINGPARTY_SINGLE_LOGOUT_BINDING);
		this.jdbcOperations.update(SAVE_RP_REGISTRATION_SQL, "okta", ENTITY_ID, NAME_ID_FORMAT, ACS_LOCATION,
				ACS_BINDING, this.signingCredentials.getBytes(StandardCharsets.UTF_8),
				this.decryptionCredentials.getBytes(StandardCharsets.UTF_8), SINGLE_LOGOUT_URL,
				SINGLE_LOGOUT_RESPONSE_URL, SINGLE_LOGOUT_BINDING, ASSERTINGPARTY_ENTITY_ID, null,
				ASSERTINGPARTY_SINGLE_SIGNON_URL, ASSERTINGPARTY_SINGLE_SIGNON_BINDING,
				ASSERTINGPARTY_SINGLE_SIGNON_SIGN_REQUEST,
				this.assertingpartyVerificationCredentials.getBytes(StandardCharsets.UTF_8),
				ASSERTINGPARTY_SINGLE_LOGOUT_URL, ASSERTINGPARTY_SINGLE_LOGOUT_RESPONSE_URL,
				ASSERTINGPARTY_SINGLE_LOGOUT_BINDING);

		Iterator<RelyingPartyRegistration> iterator = this.repository.iterator();

		RelyingPartyRegistration adfs = iterator.next();
		assertThat(adfs).isNotNull();
		assertThat(adfs.getRegistrationId()).isEqualTo(REGISTRATION_ID);
		assertThat(adfs.getEntityId()).isEqualTo(ENTITY_ID);
		assertThat(adfs.getNameIdFormat()).isEqualTo(NAME_ID_FORMAT);
		assertThat(adfs.getAssertionConsumerServiceLocation()).isEqualTo(ACS_LOCATION);
		assertThat(adfs.getAssertionConsumerServiceBinding()).isEqualTo(Saml2MessageBinding.from(ACS_BINDING));
		assertThat(adfs.getSingleLogoutServiceLocation()).isEqualTo(SINGLE_LOGOUT_URL);
		assertThat(adfs.getSingleLogoutServiceResponseLocation()).isEqualTo(SINGLE_LOGOUT_RESPONSE_URL);
		assertThat(adfs.getSingleLogoutServiceBinding()).isEqualTo(Saml2MessageBinding.from(SINGLE_LOGOUT_BINDING));
		assertThat(adfs.getSigningX509Credentials()).hasSize(1);
		assertThat(adfs.getDecryptionX509Credentials()).hasSize(1);
		AssertingPartyMetadata apm = adfs.getAssertingPartyMetadata();
		assertThat(apm.getEntityId()).isEqualTo(ASSERTINGPARTY_ENTITY_ID);
		assertThat(apm.getSingleSignOnServiceLocation()).isEqualTo(ASSERTINGPARTY_SINGLE_SIGNON_URL);
		assertThat(apm.getSingleSignOnServiceBinding())
			.isEqualTo(Saml2MessageBinding.from(ASSERTINGPARTY_SINGLE_SIGNON_BINDING));
		assertThat(apm.getWantAuthnRequestsSigned()).isTrue();
		assertThat(apm.getVerificationX509Credentials()).hasSize(1);
		assertThat(apm.getSingleLogoutServiceLocation()).isEqualTo(ASSERTINGPARTY_SINGLE_LOGOUT_URL);
		assertThat(apm.getSingleLogoutServiceResponseLocation()).isEqualTo(ASSERTINGPARTY_SINGLE_LOGOUT_RESPONSE_URL);
		assertThat(apm.getSingleLogoutServiceBinding())
			.isEqualTo(Saml2MessageBinding.from(ASSERTINGPARTY_SINGLE_LOGOUT_BINDING));

		RelyingPartyRegistration okta = iterator.next();
		assertThat(okta).isNotNull();
		assertThat(okta.getRegistrationId()).isEqualTo("okta");
	}

	private static EmbeddedDatabase createDb() {
		return createDb(RP_REGISTRATION_SCHEMA_SQL_RESOURCE);
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

	private RSAPrivateKey loadPrivateKey(String path) {
		try (InputStream is = new ClassPathResource(path).getInputStream()) {
			return RsaKeyConverters.pkcs8().convert(is);
		}
		catch (Exception ex) {
			throw new RuntimeException("Error loading private key from " + path, ex);
		}
	}

}
