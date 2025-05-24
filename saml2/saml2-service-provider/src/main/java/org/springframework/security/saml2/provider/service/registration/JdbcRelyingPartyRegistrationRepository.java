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

import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.function.Consumer;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cryptacular.util.KeyPairUtil;
import org.opensaml.security.x509.X509Support;

import org.springframework.core.log.LogMessage;
import org.springframework.jdbc.core.ArgumentPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.SqlParameterValue;
import org.springframework.jdbc.support.lob.DefaultLobHandler;
import org.springframework.jdbc.support.lob.LobHandler;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * A JDBC implementation of {@link RelyingPartyRegistrationRepository}. Also implements
 * {@link Iterable} to simplify the default login page.
 */
public class JdbcRelyingPartyRegistrationRepository implements IterableRelyingPartyRegistrationRepository {

	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

	// @formatter:off
	static final String COLUMN_NAMES = "id, "
			+ "entity_id, "
			+ "name_id_format, "
			+ "acs_location, "
			+ "acs_binding, "
			+ "signing_credentials, "
			+ "decryption_credentials, "
			+ "singlelogout_url, "
			+ "singlelogout_response_url, "
			+ "singlelogout_binding, "
			+ "assertingparty_entity_id, "
			+ "assertingparty_metadata_uri, "
			+ "assertingparty_singlesignon_url, "
			+ "assertingparty_singlesignon_binding, "
			+ "assertingparty_singlesignon_sign_request, "
			+ "assertingparty_verification_credentials, "
			+ "assertingparty_singlelogout_url, "
			+ "assertingparty_singlelogout_response_url, "
			+ "assertingparty_singlelogout_binding";
	// @formatter:on

	private static final String TABLE_NAME = "saml2_relying_party_registration";

	private static final String PK_FILTER = "id = ?";

	private static final String ENTITY_ID_FILTER = "entity_id = ?";

	// @formatter:off
	private static final String LOAD_BY_ID_SQL = "SELECT " + COLUMN_NAMES
			+ " FROM " + TABLE_NAME
			+ " WHERE " + PK_FILTER;

	private static final String LOAD_BY_ENTITY_ID_SQL = "SELECT " + COLUMN_NAMES
			+ " FROM " + TABLE_NAME
			+ " WHERE " + ENTITY_ID_FILTER;

	private static final String LOAD_ALL_SQL = "SELECT " + COLUMN_NAMES
			+ " FROM " + TABLE_NAME;
	// @formatter:on

	protected final JdbcOperations jdbcOperations;

	protected RowMapper<RelyingPartyRegistration> relyingPartyRegistrationRowMapper;

	protected final LobHandler lobHandler;

	/**
	 * Constructs a {@code JdbcRelyingPartyRegistrationRepository} using the provided
	 * parameters.
	 * @param jdbcOperations the JDBC operations
	 */
	public JdbcRelyingPartyRegistrationRepository(JdbcOperations jdbcOperations) {
		this(jdbcOperations, new DefaultLobHandler());
	}

	/**
	 * Constructs a {@code JdbcRelyingPartyRegistrationRepository} using the provided
	 * parameters.
	 * @param jdbcOperations the JDBC operations
	 * @param lobHandler the handler for large binary fields and large text fields
	 */
	public JdbcRelyingPartyRegistrationRepository(JdbcOperations jdbcOperations, LobHandler lobHandler) {
		Assert.notNull(jdbcOperations, "jdbcOperations cannot be null");
		Assert.notNull(lobHandler, "lobHandler cannot be null");
		this.jdbcOperations = jdbcOperations;
		this.lobHandler = lobHandler;
		RelyingPartyRegistrationRowMapper rowMapper = new RelyingPartyRegistrationRowMapper();
		rowMapper.setLobHandler(lobHandler);
		this.relyingPartyRegistrationRowMapper = rowMapper;
	}

	/**
	 * Sets the {@link RowMapper} used for mapping the current row in
	 * {@code java.sql.ResultSet} to {@link RelyingPartyRegistration}. The default is
	 * {@link RelyingPartyRegistrationRowMapper}.
	 * @param relyingPartyRegistrationRowMapper the {@link RowMapper} used for mapping the
	 * current row in {@code java.sql.ResultSet} to {@link RelyingPartyRegistration}
	 */
	public final void setAuthorizedClientRowMapper(
			RowMapper<RelyingPartyRegistration> relyingPartyRegistrationRowMapper) {
		Assert.notNull(relyingPartyRegistrationRowMapper, "relyingPartyRegistrationRowMapper cannot be null");
		this.relyingPartyRegistrationRowMapper = relyingPartyRegistrationRowMapper;
	}

	@Override
	public RelyingPartyRegistration findByRegistrationId(String registrationId) {
		Assert.hasText(registrationId, "registrationId cannot be empty");
		SqlParameterValue[] parameters = new SqlParameterValue[] {
				new SqlParameterValue(Types.VARCHAR, registrationId) };
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters);
		List<RelyingPartyRegistration> result = this.jdbcOperations.query(LOAD_BY_ID_SQL, pss,
				this.relyingPartyRegistrationRowMapper);
		return !result.isEmpty() ? result.get(0) : null;
	}

	@Override
	public RelyingPartyRegistration findUniqueByAssertingPartyEntityId(String entityId) {
		Assert.hasText(entityId, "entityId cannot be empty");
		SqlParameterValue[] parameters = new SqlParameterValue[] { new SqlParameterValue(Types.VARCHAR, entityId) };
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters);
		List<RelyingPartyRegistration> result = this.jdbcOperations.query(LOAD_BY_ENTITY_ID_SQL, pss,
				this.relyingPartyRegistrationRowMapper);
		return !result.isEmpty() ? result.get(0) : null;
	}

	@Override
	public Iterator<RelyingPartyRegistration> iterator() {
		List<RelyingPartyRegistration> result = this.jdbcOperations.query(LOAD_ALL_SQL,
				this.relyingPartyRegistrationRowMapper);
		return result.iterator();
	}

	/**
	 * The default {@link RowMapper} that maps the current row in
	 * {@code java.sql.ResultSet} to {@link RelyingPartyRegistration}.
	 */
	public static class RelyingPartyRegistrationRowMapper implements RowMapper<RelyingPartyRegistration> {

		private final Log logger = LogFactory.getLog(getClass());

		protected LobHandler lobHandler = new DefaultLobHandler();

		public final void setLobHandler(LobHandler lobHandler) {
			Assert.notNull(lobHandler, "lobHandler cannot be null");
			this.lobHandler = lobHandler;
		}

		@Override
		public RelyingPartyRegistration mapRow(ResultSet rs, int rowNum) throws SQLException {
			String registrationId = rs.getString("id");
			String entityId = StringUtils.hasText(rs.getString("entity_id")) ? rs.getString("entity_id")
					: "{baseUrl}/saml2/service-provider-metadata/{registrationId}";
			String nameIdFormat = rs.getString("name_id_format");
			String acsLocation = StringUtils.hasText(rs.getString("acs_location")) ? rs.getString("acs_location")
					: "{baseUrl}/login/saml2/sso/{registrationId}";
			String acsBinding = StringUtils.hasText(rs.getString("acs_binding")) ? rs.getString("acs_binding")
					: Saml2MessageBinding.POST.getUrn();
			List<Credential> signingCredentials;
			try {
				signingCredentials = parseCredentials(getLobValue(rs, "signing_credentials"));
			}
			catch (JsonProcessingException ex) {
				this.logger.error(LogMessage.format("Signing credentials of %s could not be parsed.", registrationId),
						ex);
				return null;
			}
			List<Credential> decryptionCredentials;
			try {
				decryptionCredentials = parseCredentials(getLobValue(rs, "decryption_credentials"));
			}
			catch (JsonProcessingException ex) {
				this.logger
					.error(LogMessage.format("Decryption credentials of %s could not be parsed.", registrationId), ex);
				return null;
			}
			String singleLogoutUrl = rs.getString("singlelogout_url");
			String singleLogoutResponseUrl = rs.getString("singlelogout_response_url");
			Saml2MessageBinding singleLogoutBinding = Saml2MessageBinding.from(rs.getString("singlelogout_binding"));
			String assertingPartyEntityId = rs.getString("assertingparty_entity_id");
			String assertingPartyMetadataUri = rs.getString("assertingparty_metadata_uri");
			String assertingPartySingleSignOnUrl = rs.getString("assertingparty_singlesignon_url");
			Saml2MessageBinding assertingPartySingleSignOnBinding = Saml2MessageBinding
				.from(rs.getString("assertingparty_singlesignon_binding"));
			Boolean assertingPartySingleSignOnSignRequest = rs.getBoolean("assertingparty_singlesignon_sign_request");
			List<Certificate> assertingPartyVerificationCredentials;
			try {
				assertingPartyVerificationCredentials = parseCertificate(
						getLobValue(rs, "assertingparty_verification_credentials"));
			}
			catch (JsonProcessingException ex) {
				this.logger.error(
						LogMessage.format("Verification certificate of %s could not be parsed.", registrationId), ex);
				return null;
			}
			String assertingPartySingleLogoutUrl = rs.getString("assertingparty_singlelogout_url");
			String assertingPartySingleLogoutResponseUrl = rs.getString("assertingparty_singlelogout_response_url");
			Saml2MessageBinding assertingPartySingleLogoutBinding = Saml2MessageBinding
				.from(rs.getString("assertingparty_singlelogout_binding"));

			boolean usingMetadata = StringUtils.hasText(assertingPartyMetadataUri);
			RelyingPartyRegistration.Builder builder = (!usingMetadata)
					? RelyingPartyRegistration.withRegistrationId(registrationId)
					: createBuilderUsingMetadata(assertingPartyEntityId, assertingPartyMetadataUri)
						.registrationId(registrationId);
			builder.assertionConsumerServiceLocation(acsLocation);
			builder.assertionConsumerServiceBinding(Saml2MessageBinding.from(acsBinding));
			builder.assertingPartyMetadata(mapAssertingParty(assertingPartyEntityId, assertingPartySingleSignOnBinding,
					assertingPartySingleSignOnUrl, assertingPartySingleSignOnSignRequest,
					assertingPartySingleLogoutBinding, assertingPartySingleLogoutResponseUrl,
					assertingPartySingleLogoutUrl));

			for (Credential credential : signingCredentials) {
				try {
					Saml2X509Credential signingCredential = asSigningCredential(credential);
					builder.signingX509Credentials((credentials) -> credentials.add(signingCredential));
				}
				catch (Exception ex) {
					this.logger.error(LogMessage.format("Signing credentials of %s must have a valid certificate.",
							registrationId), ex);
					return null;
				}
			}
			for (Credential credential : decryptionCredentials) {
				try {
					Saml2X509Credential decryptionCredential = asDecryptionCredential(credential);
					builder.decryptionX509Credentials((credentials) -> credentials.add(decryptionCredential));
				}
				catch (Exception ex) {
					this.logger.error(LogMessage.format("Decryption credentials of %s must have a valid certificate.",
							registrationId), ex);
					return null;
				}
			}
			List<Saml2X509Credential> verificationCredentials = new ArrayList<>();
			for (Certificate certificate : assertingPartyVerificationCredentials) {
				try {
					verificationCredentials.add(asVerificationCredential(certificate));
				}
				catch (Exception ex) {
					this.logger.error(LogMessage.format("Verification credentials of %s must have a valid certificate.",
							registrationId), ex);
					return null;
				}
			}
			builder.assertingPartyMetadata((details) -> details
				.verificationX509Credentials((credentials) -> credentials.addAll(verificationCredentials)));
			builder.singleLogoutServiceLocation(singleLogoutUrl);
			builder.singleLogoutServiceResponseLocation(singleLogoutResponseUrl);
			builder.singleLogoutServiceBinding(singleLogoutBinding);
			builder.entityId(entityId);
			builder.nameIdFormat(nameIdFormat);
			RelyingPartyRegistration registration = builder.build();
			boolean signRequest = registration.getAssertingPartyMetadata().getWantAuthnRequestsSigned();
			if (signRequest && signingCredentials.isEmpty()) {
				this.logger
					.error(LogMessage.format("Signing credentials of %s must not be empty when authentication requests "
							+ "require signing.", registrationId));
				return null;
			}
			return registration;
		}

		private Saml2X509Credential asSigningCredential(Credential credential) throws Exception {
			RSAPrivateKey privateKey = readPrivateKey(credential.getPrivateKey());
			X509Certificate certificate = readCertificate(credential.getCertificate());
			return new Saml2X509Credential(privateKey, certificate,
					Saml2X509Credential.Saml2X509CredentialType.SIGNING);
		}

		private Saml2X509Credential asDecryptionCredential(Credential credential) throws Exception {
			RSAPrivateKey privateKey = readPrivateKey(credential.getPrivateKey());
			X509Certificate certificate = readCertificate(credential.getCertificate());
			return new Saml2X509Credential(privateKey, certificate,
					Saml2X509Credential.Saml2X509CredentialType.DECRYPTION);
		}

		private Saml2X509Credential asVerificationCredential(Certificate certificate) throws Exception {
			X509Certificate x509Certificate = readCertificate(certificate.getCertificate());
			return new Saml2X509Credential(x509Certificate, Saml2X509Credential.Saml2X509CredentialType.ENCRYPTION,
					Saml2X509Credential.Saml2X509CredentialType.VERIFICATION);
		}

		private RSAPrivateKey readPrivateKey(String privateKey) {
			return (RSAPrivateKey) KeyPairUtil.decodePrivateKey(privateKey.getBytes(StandardCharsets.UTF_8));
		}

		private X509Certificate readCertificate(String certificate) throws CertificateException {
			return X509Support.decodeCertificate(certificate);
		}

		private Consumer<AssertingPartyMetadata.Builder<?>> mapAssertingParty(String assertingPartyEntityId,
				Saml2MessageBinding assertingPartySingleSignOnBinding, String assertingPartySingleSignOnUrl,
				Boolean assertingPartySingleSignOnSignRequest, Saml2MessageBinding assertingPartySingleLogoutBinding,
				String assertingPartySingleLogoutResponseUrl, String assertingPartySingleLogoutUrl) {
			return (details) -> {
				applyingWhenNonNull(assertingPartyEntityId, details::entityId);
				applyingWhenNonNull(assertingPartySingleSignOnBinding, details::singleSignOnServiceBinding);
				applyingWhenNonNull(assertingPartySingleSignOnUrl, details::singleSignOnServiceLocation);
				applyingWhenNonNull(assertingPartySingleSignOnSignRequest, details::wantAuthnRequestsSigned);
				applyingWhenNonNull(assertingPartySingleLogoutUrl, details::singleLogoutServiceLocation);
				applyingWhenNonNull(assertingPartySingleLogoutResponseUrl,
						details::singleLogoutServiceResponseLocation);
				applyingWhenNonNull(assertingPartySingleLogoutBinding, details::singleLogoutServiceBinding);
			};
		}

		private <T> void applyingWhenNonNull(T value, Consumer<T> consumer) {
			if (value != null) {
				consumer.accept(value);
			}
		}

		private RelyingPartyRegistration.Builder createBuilderUsingMetadata(String assertingPartyEntityId,
				String assertingPartyMetadataUri) {
			Collection<RelyingPartyRegistration.Builder> candidates = RelyingPartyRegistrations
				.collectionFromMetadataLocation(assertingPartyMetadataUri);
			for (RelyingPartyRegistration.Builder candidate : candidates) {
				if (assertingPartyEntityId == null || assertingPartyEntityId.equals(getEntityId(candidate))) {
					return candidate;
				}
			}
			throw new IllegalStateException("No relying party with Entity ID '" + assertingPartyEntityId + "' found");
		}

		private Object getEntityId(RelyingPartyRegistration.Builder candidate) {
			String[] result = new String[1];
			candidate.assertingPartyMetadata((builder) -> result[0] = builder.build().getEntityId());
			return result[0];
		}

		private List<Credential> parseCredentials(String credentials) throws JsonProcessingException {
			if (!StringUtils.hasText(credentials)) {
				return new ArrayList<>();
			}
			return OBJECT_MAPPER.readValue(credentials, new TypeReference<>() {
			});
		}

		private List<Certificate> parseCertificate(String certificate) throws JsonProcessingException {
			if (!StringUtils.hasText(certificate)) {
				return new ArrayList<>();
			}
			return OBJECT_MAPPER.readValue(certificate, new TypeReference<>() {
			});
		}

		private String getLobValue(ResultSet rs, String columnName) throws SQLException {
			String columnValue = null;
			byte[] columnValueBytes = this.lobHandler.getBlobAsBytes(rs, columnName);
			if (columnValueBytes != null) {
				columnValue = new String(columnValueBytes, StandardCharsets.UTF_8);
			}
			return columnValue;
		}

	}

	public static class Certificate {

		private String certificate;

		public Certificate() {
		}

		public Certificate(String certificate) {
			this.certificate = certificate;
		}

		public String getCertificate() {
			return this.certificate;
		}

		public void setCertificate(String certificate) {
			this.certificate = certificate;
		}

	}

	public static class Credential {

		private String privateKey;

		private String certificate;

		public Credential() {
		}

		public Credential(String privateKey, String certificate) {
			this.privateKey = privateKey;
			this.certificate = certificate;
		}

		public String getPrivateKey() {
			return this.privateKey;
		}

		public void setPrivateKey(String privateKey) {
			this.privateKey = privateKey;
		}

		public String getCertificate() {
			return this.certificate;
		}

		public void setCertificate(String certificate) {
			this.certificate = certificate;
		}

	}

}
