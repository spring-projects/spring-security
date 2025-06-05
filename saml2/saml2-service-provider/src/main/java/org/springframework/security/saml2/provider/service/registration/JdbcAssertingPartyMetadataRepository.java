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

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.function.Function;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.core.serializer.DefaultDeserializer;
import org.springframework.core.serializer.DefaultSerializer;
import org.springframework.core.serializer.Deserializer;
import org.springframework.core.serializer.Serializer;
import org.springframework.jdbc.core.ArgumentPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.SqlParameterValue;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration.AssertingPartyDetails;
import org.springframework.util.Assert;
import org.springframework.util.function.ThrowingFunction;

/**
 * A JDBC implementation of {@link AssertingPartyMetadataRepository}.
 *
 * @author Cathy Wang
 * @since 7.0
 */
public final class JdbcAssertingPartyMetadataRepository implements AssertingPartyMetadataRepository {

	private final JdbcOperations jdbcOperations;

	private RowMapper<AssertingPartyMetadata> assertingPartyMetadataRowMapper = new AssertingPartyMetadataRowMapper(
			ResultSet::getBytes);

	private final AssertingPartyMetadataParametersMapper assertingPartyMetadataParametersMapper = new AssertingPartyMetadataParametersMapper();

	// @formatter:off
	static final String COLUMN_NAMES = "entity_id, "
			+ "singlesignon_url, "
			+ "singlesignon_binding, "
			+ "singlesignon_sign_request, "
			+ "signing_algorithms, "
			+ "verification_credentials, "
			+ "encryption_credentials, "
			+ "singlelogout_url, "
			+ "singlelogout_response_url, "
			+ "singlelogout_binding";
	// @formatter:on

	private static final String TABLE_NAME = "saml2_asserting_party_metadata";

	private static final String ENTITY_ID_FILTER = "entity_id = ?";

	// @formatter:off
	private static final String LOAD_BY_ID_SQL = "SELECT " + COLUMN_NAMES
			+ " FROM " + TABLE_NAME
			+ " WHERE " + ENTITY_ID_FILTER;

	private static final String LOAD_ALL_SQL = "SELECT " + COLUMN_NAMES
			+ " FROM " + TABLE_NAME;
	// @formatter:on

	// @formatter:off
	private static final String SAVE_CREDENTIAL_RECORD_SQL = "INSERT INTO " + TABLE_NAME
			+ " (" + COLUMN_NAMES + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
	// @formatter:on

	// @formatter:off
	private static final String UPDATE_CREDENTIAL_RECORD_SQL = "UPDATE " + TABLE_NAME
			+ " SET singlesignon_url = ?, "
			+ "singlesignon_binding = ?, "
			+ "singlesignon_sign_request = ?, "
			+ "signing_algorithms = ?, "
			+ "verification_credentials = ?, "
			+ "encryption_credentials = ?, "
			+ "singlelogout_url = ?, "
			+ "singlelogout_response_url = ?, "
			+ "singlelogout_binding = ?"
			+ " WHERE " + ENTITY_ID_FILTER;
	// @formatter:on

	/**
	 * Constructs a {@code JdbcRelyingPartyRegistrationRepository} using the provided
	 * parameters.
	 * @param jdbcOperations the JDBC operations
	 */
	public JdbcAssertingPartyMetadataRepository(JdbcOperations jdbcOperations) {
		Assert.notNull(jdbcOperations, "jdbcOperations cannot be null");
		this.jdbcOperations = jdbcOperations;
	}

	/**
	 * Sets the {@link RowMapper} used for mapping the current row in
	 * {@code java.sql.ResultSet} to {@link AssertingPartyMetadata}. The default is
	 * {@link AssertingPartyMetadataRowMapper}.
	 * @param assertingPartyMetadataRowMapper the {@link RowMapper} used for mapping the
	 * current row in {@code java.sql.ResultSet} to {@link AssertingPartyMetadata}
	 */
	public void setAssertingPartyMetadataRowMapper(RowMapper<AssertingPartyMetadata> assertingPartyMetadataRowMapper) {
		Assert.notNull(assertingPartyMetadataRowMapper, "assertingPartyMetadataRowMapper cannot be null");
		this.assertingPartyMetadataRowMapper = assertingPartyMetadataRowMapper;
	}

	@Override
	public AssertingPartyMetadata findByEntityId(String entityId) {
		Assert.hasText(entityId, "entityId cannot be empty");
		SqlParameterValue[] parameters = new SqlParameterValue[] { new SqlParameterValue(Types.VARCHAR, entityId) };
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters);
		List<AssertingPartyMetadata> result = this.jdbcOperations.query(LOAD_BY_ID_SQL, pss,
				this.assertingPartyMetadataRowMapper);
		return !result.isEmpty() ? result.get(0) : null;
	}

	@Override
	public Iterator<AssertingPartyMetadata> iterator() {
		List<AssertingPartyMetadata> result = this.jdbcOperations.query(LOAD_ALL_SQL,
				this.assertingPartyMetadataRowMapper);
		return result.iterator();
	}

	/**
	 * Persist this {@link AssertingPartyMetadata}
	 * @param metadata the metadata to persist
	 */
	public void save(AssertingPartyMetadata metadata) {
		Assert.notNull(metadata, "metadata cannot be null");
		int rows = updateCredentialRecord(metadata);
		if (rows == 0) {
			insertCredentialRecord(metadata);
		}
	}

	private void insertCredentialRecord(AssertingPartyMetadata metadata) {
		List<SqlParameterValue> parameters = this.assertingPartyMetadataParametersMapper.apply(metadata);
		this.jdbcOperations.update(SAVE_CREDENTIAL_RECORD_SQL, parameters.toArray());
	}

	private int updateCredentialRecord(AssertingPartyMetadata metadata) {
		List<SqlParameterValue> parameters = this.assertingPartyMetadataParametersMapper.apply(metadata);
		SqlParameterValue credentialId = parameters.remove(0);
		parameters.add(credentialId);
		return this.jdbcOperations.update(UPDATE_CREDENTIAL_RECORD_SQL, parameters.toArray());
	}

	/**
	 * The default {@link RowMapper} that maps the current row in
	 * {@code java.sql.ResultSet} to {@link AssertingPartyMetadata}.
	 */
	private static final class AssertingPartyMetadataRowMapper implements RowMapper<AssertingPartyMetadata> {

		private final Log logger = LogFactory.getLog(AssertingPartyMetadataRowMapper.class);

		private final Deserializer<Object> deserializer = new DefaultDeserializer();

		private final GetBytes getBytes;

		AssertingPartyMetadataRowMapper(GetBytes getBytes) {
			this.getBytes = getBytes;
		}

		@Override
		public AssertingPartyMetadata mapRow(ResultSet rs, int rowNum) throws SQLException {
			String entityId = rs.getString("entity_id");
			String singleSignOnUrl = rs.getString("singlesignon_url");
			Saml2MessageBinding singleSignOnBinding = Saml2MessageBinding.from(rs.getString("singlesignon_binding"));
			boolean singleSignOnSignRequest = rs.getBoolean("singlesignon_sign_request");
			String singleLogoutUrl = rs.getString("singlelogout_url");
			String singleLogoutResponseUrl = rs.getString("singlelogout_response_url");
			Saml2MessageBinding singleLogoutBinding = Saml2MessageBinding.from(rs.getString("singlelogout_binding"));
			byte[] signingAlgorithmsBytes = this.getBytes.getBytes(rs, "signing_algorithms");
			byte[] verificationCredentialsBytes = this.getBytes.getBytes(rs, "verification_credentials");
			byte[] encryptionCredentialsBytes = this.getBytes.getBytes(rs, "encryption_credentials");

			AssertingPartyMetadata.Builder<?> builder = new AssertingPartyDetails.Builder();
			try {
				if (signingAlgorithmsBytes != null) {
					List<String> signingAlgorithms = (List<String>) this.deserializer
						.deserializeFromByteArray(signingAlgorithmsBytes);
					builder.signingAlgorithms((algorithms) -> algorithms.addAll(signingAlgorithms));
				}
				if (verificationCredentialsBytes != null) {
					Collection<Saml2X509Credential> verificationCredentials = (Collection<Saml2X509Credential>) this.deserializer
						.deserializeFromByteArray(verificationCredentialsBytes);
					builder.verificationX509Credentials((credentials) -> credentials.addAll(verificationCredentials));
				}
				if (encryptionCredentialsBytes != null) {
					Collection<Saml2X509Credential> encryptionCredentials = (Collection<Saml2X509Credential>) this.deserializer
						.deserializeFromByteArray(encryptionCredentialsBytes);
					builder.encryptionX509Credentials((credentials) -> credentials.addAll(encryptionCredentials));
				}
			}
			catch (Exception ex) {
				this.logger.debug(LogMessage.format("Parsing serialized credentials for entity %s failed", entityId),
						ex);
				return null;
			}

			builder.entityId(entityId)
				.wantAuthnRequestsSigned(singleSignOnSignRequest)
				.singleSignOnServiceLocation(singleSignOnUrl)
				.singleSignOnServiceBinding(singleSignOnBinding)
				.singleLogoutServiceLocation(singleLogoutUrl)
				.singleLogoutServiceBinding(singleLogoutBinding)
				.singleLogoutServiceResponseLocation(singleLogoutResponseUrl);
			return builder.build();
		}

	}

	private static class AssertingPartyMetadataParametersMapper
			implements Function<AssertingPartyMetadata, List<SqlParameterValue>> {

		private final Serializer<Object> serializer = new DefaultSerializer();

		@Override
		public List<SqlParameterValue> apply(AssertingPartyMetadata record) {
			List<SqlParameterValue> parameters = new ArrayList<>();

			parameters.add(new SqlParameterValue(Types.VARCHAR, record.getEntityId()));
			parameters.add(new SqlParameterValue(Types.VARCHAR, record.getSingleSignOnServiceLocation()));
			parameters.add(new SqlParameterValue(Types.VARCHAR, record.getSingleSignOnServiceBinding().getUrn()));
			parameters.add(new SqlParameterValue(Types.BOOLEAN, record.getWantAuthnRequestsSigned()));
			ThrowingFunction<List<String>, byte[]> algorithms = this.serializer::serializeToByteArray;
			parameters.add(new SqlParameterValue(Types.BLOB, algorithms.apply(record.getSigningAlgorithms())));
			ThrowingFunction<Collection<Saml2X509Credential>, byte[]> credentials = this.serializer::serializeToByteArray;
			parameters
				.add(new SqlParameterValue(Types.BLOB, credentials.apply(record.getVerificationX509Credentials())));
			parameters.add(new SqlParameterValue(Types.BLOB, credentials.apply(record.getEncryptionX509Credentials())));
			parameters.add(new SqlParameterValue(Types.VARCHAR, record.getSingleLogoutServiceLocation()));
			parameters.add(new SqlParameterValue(Types.VARCHAR, record.getSingleLogoutServiceResponseLocation()));
			parameters.add(new SqlParameterValue(Types.VARCHAR, record.getSingleLogoutServiceBinding().getUrn()));

			return parameters;
		}

	}

	private interface GetBytes {

		byte[] getBytes(ResultSet rs, String columnName) throws SQLException;

	}

}
