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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.function.Function;

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

	private final RowMapper<AssertingPartyMetadata> assertingPartyMetadataRowMapper = new AssertingPartyMetadataRowMapper();

	private final AssertingPartyMetadataParametersMapper assertingPartyMetadataParametersMapper = new AssertingPartyMetadataParametersMapper();

	// @formatter:off
	static final String[] COLUMN_NAMES = { "entity_id",
			"single_sign_on_service_location",
			"single_sign_on_service_binding",
			"want_authn_requests_signed",
			"signing_algorithms",
			"verification_credentials",
			"encryption_credentials",
			"single_logout_service_location",
			"single_logout_service_response_location",
			"single_logout_service_binding" };

	// @formatter:on

	private static final String TABLE_NAME = "saml2_asserting_party_metadata";

	private static final String ENTITY_ID_FILTER = "entity_id = ?";

	// @formatter:off
	private static final String LOAD_BY_ID_SQL = "SELECT " + String.join(",", COLUMN_NAMES)
			+ " FROM " + TABLE_NAME
			+ " WHERE " + ENTITY_ID_FILTER;

	private static final String LOAD_ALL_SQL = "SELECT " + String.join(",", COLUMN_NAMES)
			+ " FROM " + TABLE_NAME;
	// @formatter:on

	// @formatter:off
	private static final String SAVE_CREDENTIAL_RECORD_SQL = "INSERT INTO " + TABLE_NAME
			+ " (" + String.join(",", COLUMN_NAMES) + ") VALUES (" + String.join(",", Collections.nCopies(COLUMN_NAMES.length, "?")) + ")";
	// @formatter:on

	// @formatter:off
	private static final String UPDATE_CREDENTIAL_RECORD_SQL = "UPDATE " + TABLE_NAME
			+ " SET " + String.join(" = ?,", Arrays.copyOfRange(COLUMN_NAMES, 1, COLUMN_NAMES.length))
			+ " = ?"
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

		private final Deserializer<Object> deserializer = new DefaultDeserializer();

		@Override
		public AssertingPartyMetadata mapRow(ResultSet rs, int rowNum) throws SQLException {
			String entityId = rs.getString(COLUMN_NAMES[0]);
			String singleSignOnUrl = rs.getString(COLUMN_NAMES[1]);
			Saml2MessageBinding singleSignOnBinding = Saml2MessageBinding.from(rs.getString(COLUMN_NAMES[2]));
			boolean singleSignOnSignRequest = rs.getBoolean(COLUMN_NAMES[3]);
			List<String> algorithms = List.of(rs.getString(COLUMN_NAMES[4]).split(","));
			byte[] verificationCredentialsBytes = rs.getBytes(COLUMN_NAMES[5]);
			byte[] encryptionCredentialsBytes = rs.getBytes(COLUMN_NAMES[6]);
			ThrowingFunction<byte[], Collection<Saml2X509Credential>> credentials = (
					bytes) -> (Collection<Saml2X509Credential>) this.deserializer.deserializeFromByteArray(bytes);
			AssertingPartyMetadata.Builder<?> builder = new AssertingPartyDetails.Builder();
			Collection<Saml2X509Credential> verificationCredentials = credentials.apply(verificationCredentialsBytes);
			Collection<Saml2X509Credential> encryptionCredentials = (encryptionCredentialsBytes != null)
					? credentials.apply(encryptionCredentialsBytes) : List.of();
			String singleLogoutUrl = rs.getString(COLUMN_NAMES[7]);
			String singleLogoutResponseUrl = rs.getString(COLUMN_NAMES[8]);
			Saml2MessageBinding singleLogoutBinding = Saml2MessageBinding.from(rs.getString(COLUMN_NAMES[9]));

			builder.entityId(entityId)
				.wantAuthnRequestsSigned(singleSignOnSignRequest)
				.singleSignOnServiceLocation(singleSignOnUrl)
				.singleSignOnServiceBinding(singleSignOnBinding)
				.singleLogoutServiceLocation(singleLogoutUrl)
				.singleLogoutServiceBinding(singleLogoutBinding)
				.singleLogoutServiceResponseLocation(singleLogoutResponseUrl)
				.signingAlgorithms((a) -> a.addAll(algorithms))
				.verificationX509Credentials((c) -> c.addAll(verificationCredentials))
				.encryptionX509Credentials((c) -> c.addAll(encryptionCredentials));
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
			parameters.add(new SqlParameterValue(Types.BLOB, String.join(",", record.getSigningAlgorithms())));
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

}
