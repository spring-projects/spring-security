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

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.ArgumentPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.SqlParameterValue;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.util.Assert;

/**
 * A JDBC implementation of an {@link PublicKeyCredentialUserEntityRepository} that uses a
 * {@link JdbcOperations} for {@link PublicKeyCredentialUserEntity} persistence.
 *
 * <b>NOTE:</b> This {@code PublicKeyCredentialUserEntityRepository} depends on the table
 * definition described in
 * "classpath:org/springframework/security/user-entities-schema.sql" and therefore MUST be
 * defined in the database schema.
 *
 * @author Max Batischev
 * @since 6.5
 * @see PublicKeyCredentialUserEntityRepository
 * @see PublicKeyCredentialUserEntity
 * @see JdbcOperations
 * @see RowMapper
 */
public final class JdbcPublicKeyCredentialUserEntityRepository implements PublicKeyCredentialUserEntityRepository {

	private RowMapper<PublicKeyCredentialUserEntity> userEntityRowMapper = new UserEntityRecordRowMapper();

	private Function<PublicKeyCredentialUserEntity, List<SqlParameterValue>> userEntityParametersMapper = new UserEntityParametersMapper();

	private final JdbcOperations jdbcOperations;

	private static final String TABLE_NAME = "user_entities";

	// @formatter:off
	private static final String COLUMN_NAMES = "id, "
			+ "name, "
			+ "display_name ";
	// @formatter:on

	// @formatter:off
	private static final String SAVE_USER_SQL = "INSERT INTO " + TABLE_NAME
			+ " (" + COLUMN_NAMES + ") VALUES (?, ?, ?)";
	// @formatter:on

	private static final String ID_FILTER = "id = ? ";

	private static final String USER_NAME_FILTER = "name = ? ";

	// @formatter:off
	private static final String FIND_USER_BY_ID_SQL = "SELECT " + COLUMN_NAMES
			+ " FROM " + TABLE_NAME
			+ " WHERE " + ID_FILTER;
	// @formatter:on

	// @formatter:off
	private static final String FIND_USER_BY_NAME_SQL = "SELECT " + COLUMN_NAMES
			+ " FROM " + TABLE_NAME
			+ " WHERE " + USER_NAME_FILTER;
	// @formatter:on

	private static final String DELETE_USER_SQL = "DELETE FROM " + TABLE_NAME + " WHERE " + ID_FILTER;

	// @formatter:off
	private static final String UPDATE_USER_SQL = "UPDATE " + TABLE_NAME
			+ " SET name = ?, display_name = ? "
			+ " WHERE " + ID_FILTER;
	// @formatter:on

	/**
	 * Constructs a {@code JdbcPublicKeyCredentialUserEntityRepository} using the provided
	 * parameters.
	 * @param jdbcOperations the JDBC operations
	 */
	public JdbcPublicKeyCredentialUserEntityRepository(JdbcOperations jdbcOperations) {
		Assert.notNull(jdbcOperations, "jdbcOperations cannot be null");
		this.jdbcOperations = jdbcOperations;
	}

	@Override
	public PublicKeyCredentialUserEntity findById(Bytes id) {
		Assert.notNull(id, "id cannot be null");
		List<PublicKeyCredentialUserEntity> result = this.jdbcOperations.query(FIND_USER_BY_ID_SQL,
				this.userEntityRowMapper, id.toBase64UrlString());
		return !result.isEmpty() ? result.get(0) : null;
	}

	@Override
	public PublicKeyCredentialUserEntity findByUsername(String username) {
		Assert.hasText(username, "name cannot be null or empty");
		List<PublicKeyCredentialUserEntity> result = this.jdbcOperations.query(FIND_USER_BY_NAME_SQL,
				this.userEntityRowMapper, username);
		return !result.isEmpty() ? result.get(0) : null;
	}

	@Override
	public void save(PublicKeyCredentialUserEntity userEntity) {
		Assert.notNull(userEntity, "userEntity cannot be null");
		boolean existsUserEntity = null != this.findById(userEntity.getId());
		if (existsUserEntity) {
			updateUserEntity(userEntity);
		}
		else {
			try {
				insertUserEntity(userEntity);
			}
			catch (DuplicateKeyException ex) {
				updateUserEntity(userEntity);
			}
		}
	}

	private void insertUserEntity(PublicKeyCredentialUserEntity userEntity) {
		List<SqlParameterValue> parameters = this.userEntityParametersMapper.apply(userEntity);
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());
		this.jdbcOperations.update(SAVE_USER_SQL, pss);
	}

	private void updateUserEntity(PublicKeyCredentialUserEntity userEntity) {
		List<SqlParameterValue> parameters = this.userEntityParametersMapper.apply(userEntity);
		SqlParameterValue userEntityId = parameters.remove(0);
		parameters.add(userEntityId);
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());
		this.jdbcOperations.update(UPDATE_USER_SQL, pss);
	}

	@Override
	public void delete(Bytes id) {
		Assert.notNull(id, "id cannot be null");
		SqlParameterValue[] parameters = new SqlParameterValue[] {
				new SqlParameterValue(Types.VARCHAR, id.toBase64UrlString()), };
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters);
		this.jdbcOperations.update(DELETE_USER_SQL, pss);
	}

	private static class UserEntityParametersMapper
			implements Function<PublicKeyCredentialUserEntity, List<SqlParameterValue>> {

		@Override
		public List<SqlParameterValue> apply(PublicKeyCredentialUserEntity userEntity) {
			List<SqlParameterValue> parameters = new ArrayList<>();

			parameters.add(new SqlParameterValue(Types.VARCHAR, userEntity.getId().toBase64UrlString()));
			parameters.add(new SqlParameterValue(Types.VARCHAR, userEntity.getName()));
			parameters.add(new SqlParameterValue(Types.VARCHAR, userEntity.getDisplayName()));

			return parameters;
		}

	}

	private static class UserEntityRecordRowMapper implements RowMapper<PublicKeyCredentialUserEntity> {

		@Override
		public PublicKeyCredentialUserEntity mapRow(ResultSet rs, int rowNum) throws SQLException {
			Bytes id = Bytes.fromBase64(new String(rs.getString("id").getBytes()));
			String name = rs.getString("name");
			String displayName = rs.getString("display_name");

			return ImmutablePublicKeyCredentialUserEntity.builder().id(id).name(name).displayName(displayName).build();
		}

	}

}
