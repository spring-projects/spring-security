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

package org.springframework.security.web.webauthn.management;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

import org.jspecify.annotations.Nullable;

import org.springframework.jdbc.core.ArgumentPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.SqlParameterValue;
import org.springframework.jdbc.support.lob.LobCreator;
import org.springframework.jdbc.support.lob.LobHandler;
import org.springframework.security.web.webauthn.api.AuthenticatorTransport;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.ImmutableCredentialRecord;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCose;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 * A JDBC implementation of an {@link UserCredentialRepository} that uses a
 * {@link JdbcOperations} for {@link CredentialRecord} persistence.
 *
 * <b>NOTE:</b> This {@code UserCredentialRepository} depends on the table definition
 * described in "classpath:org/springframework/security/user-credentials-schema.sql" and
 * therefore MUST be defined in the database schema.
 *
 * @author Max Batischev
 * @since 6.5
 * @see UserCredentialRepository
 * @see CredentialRecord
 * @see JdbcOperations
 * @see RowMapper
 */
public final class JdbcUserCredentialRepository implements UserCredentialRepository {

	private RowMapper<CredentialRecord> credentialRecordRowMapper = new CredentialRecordRowMapper(ResultSet::getBytes);

	private Function<CredentialRecord, List<SqlParameterValue>> credentialRecordParametersMapper = new CredentialRecordParametersMapper();

	private SetBytes setBytes = PreparedStatement::setBytes;

	private final JdbcOperations jdbcOperations;

	private static final String TABLE_NAME = "user_credentials";

	// @formatter:off
	private static final String COLUMN_NAMES = "credential_id, "
			+ "user_entity_user_id, "
			+ "public_key, "
			+ "signature_count, "
			+ "uv_initialized, "
			+ "backup_eligible, "
			+ "authenticator_transports, "
			+ "public_key_credential_type, "
			+ "backup_state, "
			+ "attestation_object, "
			+ "attestation_client_data_json, "
			+ "created, "
			+ "last_used, "
			+ "label ";
	// @formatter:on

	// @formatter:off
	private static final String SAVE_CREDENTIAL_RECORD_SQL = "INSERT INTO " + TABLE_NAME
			+ " (" + COLUMN_NAMES + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
	// @formatter:on

	private static final String ID_FILTER = "credential_id = ? ";

	private static final String USER_ID_FILTER = "user_entity_user_id = ? ";

	// @formatter:off
	private static final String FIND_CREDENTIAL_RECORD_BY_ID_SQL = "SELECT " + COLUMN_NAMES
			+ " FROM " + TABLE_NAME
			+ " WHERE " + ID_FILTER;
	// @formatter:on

	// @formatter:off
	private static final String FIND_CREDENTIAL_RECORD_BY_USER_ID_SQL = "SELECT " + COLUMN_NAMES
			+ " FROM " + TABLE_NAME
			+ " WHERE " + USER_ID_FILTER;
	// @formatter:on

	private static final String DELETE_CREDENTIAL_RECORD_SQL = "DELETE FROM " + TABLE_NAME + " WHERE " + ID_FILTER;

	// @formatter:off
	private static final String UPDATE_CREDENTIAL_RECORD_SQL = "UPDATE " + TABLE_NAME
			+ " SET user_entity_user_id = ?, " +
			"public_key = ?, " +
			"signature_count = ?, " +
			"uv_initialized = ?, " +
			"backup_eligible = ? ," +
			"authenticator_transports = ?, " +
			"public_key_credential_type = ?, " +
			"backup_state = ?, " +
			"attestation_object = ?, " +
			"attestation_client_data_json = ?, " +
			"created = ?, " +
			"last_used = ?, " +
			"label = ?"
			+ " WHERE " + ID_FILTER;
	// @formatter:on

	/**
	 * Constructs a {@code JdbcUserCredentialRepository} using the provided parameters.
	 * @param jdbcOperations the JDBC operations
	 */
	public JdbcUserCredentialRepository(JdbcOperations jdbcOperations) {
		Assert.notNull(jdbcOperations, "jdbcOperations cannot be null");
		this.jdbcOperations = jdbcOperations;
	}

	@Override
	public void delete(Bytes credentialId) {
		Assert.notNull(credentialId, "credentialId cannot be null");
		SqlParameterValue[] parameters = new SqlParameterValue[] {
				new SqlParameterValue(Types.VARCHAR, credentialId.toBase64UrlString()), };
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters);
		this.jdbcOperations.update(DELETE_CREDENTIAL_RECORD_SQL, pss);
	}

	@Override
	public void save(CredentialRecord record) {
		Assert.notNull(record, "record cannot be null");
		int rows = updateCredentialRecord(record);
		if (rows == 0) {
			insertCredentialRecord(record);
		}
	}

	private void insertCredentialRecord(CredentialRecord record) {
		List<SqlParameterValue> parameters = this.credentialRecordParametersMapper.apply(record);
		PreparedStatementSetter pss = new BlobArgumentPreparedStatementSetter(this.setBytes, parameters.toArray());
		this.jdbcOperations.update(SAVE_CREDENTIAL_RECORD_SQL, pss);
	}

	private int updateCredentialRecord(CredentialRecord record) {
		List<SqlParameterValue> parameters = this.credentialRecordParametersMapper.apply(record);
		SqlParameterValue credentialId = parameters.remove(0);
		parameters.add(credentialId);
		PreparedStatementSetter pss = new BlobArgumentPreparedStatementSetter(this.setBytes, parameters.toArray());
		return this.jdbcOperations.update(UPDATE_CREDENTIAL_RECORD_SQL, pss);
	}

	@Override
	public @Nullable CredentialRecord findByCredentialId(Bytes credentialId) {
		Assert.notNull(credentialId, "credentialId cannot be null");
		List<CredentialRecord> result = this.jdbcOperations.query(FIND_CREDENTIAL_RECORD_BY_ID_SQL,
				this.credentialRecordRowMapper, credentialId.toBase64UrlString());
		return !result.isEmpty() ? result.get(0) : null;
	}

	@Override
	public List<CredentialRecord> findByUserId(Bytes userId) {
		Assert.notNull(userId, "userId cannot be null");
		return this.jdbcOperations.query(FIND_CREDENTIAL_RECORD_BY_USER_ID_SQL, this.credentialRecordRowMapper,
				userId.toBase64UrlString());
	}

	/**
	 * Sets a {@link LobHandler} for large binary fields and large text field parameters.
	 * @param lobHandler the lob handler
	 * @deprecated {@link LobHandler} is deprecated without replacement, as such this
	 * method will also be removed without replacement
	 */
	@Deprecated(since = "6.5", forRemoval = true)
	public void setLobHandler(LobHandler lobHandler) {
		Assert.notNull(lobHandler, "lobHandler cannot be null");
		this.setBytes = (ps, index, bytes) -> {
			try (LobCreator creator = lobHandler.getLobCreator()) {
				creator.setBlobAsBytes(ps, index, bytes);
			}
		};
		this.credentialRecordRowMapper = new CredentialRecordRowMapper(lobHandler::getBlobAsBytes);
	}

	private static class CredentialRecordParametersMapper
			implements Function<CredentialRecord, List<SqlParameterValue>> {

		@Override
		public List<SqlParameterValue> apply(CredentialRecord record) {
			List<SqlParameterValue> parameters = new ArrayList<>();

			List<String> transports = new ArrayList<>();
			if (!CollectionUtils.isEmpty(record.getTransports())) {
				for (AuthenticatorTransport transport : record.getTransports()) {
					transports.add(transport.getValue());
				}
			}

			parameters.add(new SqlParameterValue(Types.VARCHAR, record.getCredentialId().toBase64UrlString()));
			parameters.add(new SqlParameterValue(Types.VARCHAR, record.getUserEntityUserId().toBase64UrlString()));
			parameters.add(new SqlParameterValue(Types.BLOB, record.getPublicKey().getBytes()));
			parameters.add(new SqlParameterValue(Types.BIGINT, record.getSignatureCount()));
			parameters.add(new SqlParameterValue(Types.BOOLEAN, record.isUvInitialized()));
			parameters.add(new SqlParameterValue(Types.BOOLEAN, record.isBackupEligible()));
			parameters.add(new SqlParameterValue(Types.VARCHAR,
					(!CollectionUtils.isEmpty(record.getTransports())) ? String.join(",", transports) : ""));
			parameters.add(new SqlParameterValue(Types.VARCHAR,
					(record.getCredentialType() != null) ? record.getCredentialType().getValue() : null));
			parameters.add(new SqlParameterValue(Types.BOOLEAN, record.isBackupState()));
			parameters.add(new SqlParameterValue(Types.BLOB,
					(record.getAttestationObject() != null) ? record.getAttestationObject().getBytes() : null));
			parameters.add(new SqlParameterValue(Types.BLOB, (record.getAttestationClientDataJSON() != null)
					? record.getAttestationClientDataJSON().getBytes() : null));
			parameters.add(new SqlParameterValue(Types.TIMESTAMP, fromInstant(record.getCreated())));
			parameters.add(new SqlParameterValue(Types.TIMESTAMP, fromInstant(record.getLastUsed())));
			parameters.add(new SqlParameterValue(Types.VARCHAR, record.getLabel()));

			return parameters;
		}

		private @Nullable Timestamp fromInstant(Instant instant) {
			if (instant == null) {
				return null;
			}
			return Timestamp.from(instant);
		}

	}

	private interface SetBytes {

		void setBytes(PreparedStatement ps, int index, byte @Nullable [] bytes) throws SQLException;

	}

	private interface GetBytes {

		byte @Nullable [] getBytes(ResultSet rs, String columnName) throws SQLException;

	}

	private static final class BlobArgumentPreparedStatementSetter extends ArgumentPreparedStatementSetter {

		private final SetBytes setBytes;

		private BlobArgumentPreparedStatementSetter(SetBytes setBytes, Object[] args) {
			super(args);
			this.setBytes = setBytes;
		}

		@Override
		protected void doSetValue(PreparedStatement ps, int parameterPosition, @Nullable Object argValue)
				throws SQLException {
			if (argValue instanceof SqlParameterValue paramValue) {
				if (paramValue.getSqlType() == Types.BLOB) {
					if (paramValue.getValue() != null) {
						Assert.isInstanceOf(byte[].class, paramValue.getValue(),
								"Value of blob parameter must be byte[]");
					}
					byte[] valueBytes = (byte[]) paramValue.getValue();
					this.setBytes.setBytes(ps, parameterPosition, valueBytes);
					return;
				}
			}
			super.doSetValue(ps, parameterPosition, argValue);
		}

	}

	private static class CredentialRecordRowMapper implements RowMapper<CredentialRecord> {

		private final GetBytes getBytes;

		CredentialRecordRowMapper(GetBytes getBytes) {
			this.getBytes = getBytes;
		}

		@Override
		public CredentialRecord mapRow(ResultSet rs, int rowNum) throws SQLException {
			Bytes credentialId = Bytes.fromBase64(new String(rs.getString("credential_id").getBytes()));
			Bytes userEntityUserId = Bytes.fromBase64(new String(rs.getString("user_entity_user_id").getBytes()));
			ImmutablePublicKeyCose publicKey = new ImmutablePublicKeyCose(this.getBytes.getBytes(rs, "public_key"));
			long signatureCount = rs.getLong("signature_count");
			boolean uvInitialized = rs.getBoolean("uv_initialized");
			boolean backupEligible = rs.getBoolean("backup_eligible");
			PublicKeyCredentialType credentialType = PublicKeyCredentialType
				.valueOf(rs.getString("public_key_credential_type"));
			boolean backupState = rs.getBoolean("backup_state");

			Bytes attestationObject = null;
			byte[] rawAttestationObject = this.getBytes.getBytes(rs, "attestation_object");
			if (rawAttestationObject != null) {
				attestationObject = new Bytes(rawAttestationObject);
			}

			Bytes attestationClientDataJson = null;
			byte[] rawAttestationClientDataJson = this.getBytes.getBytes(rs, "attestation_client_data_json");
			if (rawAttestationClientDataJson != null) {
				attestationClientDataJson = new Bytes(rawAttestationClientDataJson);
			}

			Instant created = fromTimestamp(rs.getTimestamp("created"));
			Instant lastUsed = fromTimestamp(rs.getTimestamp("last_used"));
			String label = rs.getString("label");
			String[] transports = rs.getString("authenticator_transports").split(",");

			Set<AuthenticatorTransport> authenticatorTransports = new HashSet<>();
			for (String transport : transports) {
				authenticatorTransports.add(AuthenticatorTransport.valueOf(transport));
			}
			Assert.notNull(lastUsed, "last_used cannot be null");
			Assert.notNull(created, "created cannot be null");
			return ImmutableCredentialRecord.builder()
				.credentialId(credentialId)
				.userEntityUserId(userEntityUserId)
				.publicKey(publicKey)
				.signatureCount(signatureCount)
				.uvInitialized(uvInitialized)
				.backupEligible(backupEligible)
				.credentialType(credentialType)
				.backupState(backupState)
				.attestationObject(attestationObject)
				.attestationClientDataJSON(attestationClientDataJson)
				.created(created)
				.label(label)
				.lastUsed(lastUsed)
				.transports(authenticatorTransports)
				.build();
		}

		private @Nullable Instant fromTimestamp(Timestamp timestamp) {
			if (timestamp == null) {
				return null;
			}
			return timestamp.toInstant();
		}

	}

}
