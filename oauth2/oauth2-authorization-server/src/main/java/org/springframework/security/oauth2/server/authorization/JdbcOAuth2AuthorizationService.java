/*
 * Copyright 2020-2025 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization;

import java.nio.charset.StandardCharsets;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.context.annotation.ImportRuntimeHints;
import org.springframework.core.io.ClassPathResource;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.jdbc.core.ArgumentPreparedStatementSetter;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.SqlParameterValue;
import org.springframework.jdbc.support.lob.DefaultLobHandler;
import org.springframework.jdbc.support.lob.LobCreator;
import org.springframework.jdbc.support.lob.LobHandler;
import org.springframework.lang.Nullable;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * A JDBC implementation of an {@link OAuth2AuthorizationService} that uses a
 * {@link JdbcOperations} for {@link OAuth2Authorization} persistence.
 *
 * <p>
 * <b>IMPORTANT:</b> This {@code OAuth2AuthorizationService} depends on the table
 * definition described in
 * "classpath:org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql"
 * and therefore MUST be defined in the database schema.
 *
 * <p>
 * <b>NOTE:</b> This {@code OAuth2AuthorizationService} is a simplified JDBC
 * implementation that MAY be used in a production environment. However, it does have
 * limitations as it likely won't perform well in an environment requiring high
 * throughput. The expectation is that the consuming application will provide their own
 * implementation of {@code OAuth2AuthorizationService} that meets the performance
 * requirements for its deployment environment.
 *
 * @author Ovidiu Popa
 * @author Joe Grandja
 * @author Josh Long
 * @since 0.1.2
 * @see OAuth2AuthorizationService
 * @see OAuth2Authorization
 * @see JdbcOperations
 * @see RowMapper
 */
@ImportRuntimeHints(JdbcOAuth2AuthorizationService.JdbcOAuth2AuthorizationServiceRuntimeHintsRegistrar.class)
public class JdbcOAuth2AuthorizationService implements OAuth2AuthorizationService {

	private static final String REFRESH_TOKEN_VALUE = "refresh_token_value";

	private static final String AUTHORIZATION_CODE_VALUE = "authorization_code_value";

	private static final String ACCESS_TOKEN_VALUE = "access_token_value";

	private static final String OIDC_ID_TOKEN_VALUE = "oidc_id_token_value";

	private static final String USER_CODE_VALUE = "user_code_value";

	private static final String DEVICE_CODE_VALUE = "device_code_value";

	private static final String AUTHORIZATION_CODE_METADATA = "authorization_code_metadata";

	private static final String ACCESS_TOKEN_METADATA = "access_token_metadata";

	private static final String OIDC_ID_TOKEN_METADATA = "oidc_id_token_metadata";

	private static final String REFRESH_TOKEN_METADATA = "refresh_token_metadata";

	private static final String USER_CODE_METADATA = "user_code_metadata";

	private static final String DEVICE_CODE_METADATA = "device_code_metadata";

	// @formatter:off
	private static final String COLUMN_NAMES = "id, "
			+ "registered_client_id, "
			+ "principal_name, "
			+ "authorization_grant_type, "
			+ "authorized_scopes, "
			+ "attributes, "
			+ "state, "
			+ "authorization_code_value, "
			+ "authorization_code_issued_at, "
			+ "authorization_code_expires_at,"
			+ "authorization_code_metadata,"
			+ "access_token_value,"
			+ "access_token_issued_at,"
			+ "access_token_expires_at,"
			+ "access_token_metadata,"
			+ "access_token_type,"
			+ "access_token_scopes,"
			+ "oidc_id_token_value,"
			+ "oidc_id_token_issued_at,"
			+ "oidc_id_token_expires_at,"
			+ "oidc_id_token_metadata,"
			+ "refresh_token_value,"
			+ "refresh_token_issued_at,"
			+ "refresh_token_expires_at,"
			+ "refresh_token_metadata,"
			+ "user_code_value,"
			+ "user_code_issued_at,"
			+ "user_code_expires_at,"
			+ "user_code_metadata,"
			+ "device_code_value,"
			+ "device_code_issued_at,"
			+ "device_code_expires_at,"
			+ "device_code_metadata";
	// @formatter:on

	private static final String TABLE_NAME = "oauth2_authorization";

	private static final String PK_FILTER = "id = ?";

	private static final String UNKNOWN_TOKEN_TYPE_FILTER = "state = ? OR authorization_code_value = ? OR "
			+ "access_token_value = ? OR oidc_id_token_value = ? OR refresh_token_value = ? OR user_code_value = ? OR "
			+ "device_code_value = ?";

	private static final String STATE_FILTER = "state = ?";

	private static final String AUTHORIZATION_CODE_FILTER = "authorization_code_value = ?";

	private static final String ACCESS_TOKEN_FILTER = "access_token_value = ?";

	private static final String ID_TOKEN_FILTER = "oidc_id_token_value = ?";

	private static final String REFRESH_TOKEN_FILTER = "refresh_token_value = ?";

	private static final String USER_CODE_FILTER = "user_code_value = ?";

	private static final String DEVICE_CODE_FILTER = "device_code_value = ?";

	// @formatter:off
	private static final String LOAD_AUTHORIZATION_SQL = "SELECT " + COLUMN_NAMES
			+ " FROM " + TABLE_NAME
			+ " WHERE ";
	// @formatter:on

	// @formatter:off
	private static final String SAVE_AUTHORIZATION_SQL = "INSERT INTO " + TABLE_NAME
			+ " (" + COLUMN_NAMES + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
	// @formatter:on

	// @formatter:off
	private static final String UPDATE_AUTHORIZATION_SQL = "UPDATE " + TABLE_NAME
			+ " SET registered_client_id = ?, principal_name = ?, authorization_grant_type = ?, authorized_scopes = ?, attributes = ?, state = ?,"
			+ " authorization_code_value = ?, authorization_code_issued_at = ?, authorization_code_expires_at = ?, authorization_code_metadata = ?,"
			+ " access_token_value = ?, access_token_issued_at = ?, access_token_expires_at = ?, access_token_metadata = ?, access_token_type = ?, access_token_scopes = ?,"
			+ " oidc_id_token_value = ?, oidc_id_token_issued_at = ?, oidc_id_token_expires_at = ?, oidc_id_token_metadata = ?,"
			+ " refresh_token_value = ?, refresh_token_issued_at = ?, refresh_token_expires_at = ?, refresh_token_metadata = ?,"
			+ " user_code_value = ?, user_code_issued_at = ?, user_code_expires_at = ?, user_code_metadata = ?,"
			+ " device_code_value = ?, device_code_issued_at = ?, device_code_expires_at = ?, device_code_metadata = ?"
			+ " WHERE " + PK_FILTER;
	// @formatter:on

	private static final String REMOVE_AUTHORIZATION_SQL = "DELETE FROM " + TABLE_NAME + " WHERE " + PK_FILTER;

	private static Map<String, ColumnMetadata> columnMetadataMap;

	private final JdbcOperations jdbcOperations;

	private final LobHandler lobHandler;

	private RowMapper<OAuth2Authorization> authorizationRowMapper;

	private Function<OAuth2Authorization, List<SqlParameterValue>> authorizationParametersMapper;

	/**
	 * Constructs a {@code JdbcOAuth2AuthorizationService} using the provided parameters.
	 * @param jdbcOperations the JDBC operations
	 * @param registeredClientRepository the registered client repository
	 */
	public JdbcOAuth2AuthorizationService(JdbcOperations jdbcOperations,
			RegisteredClientRepository registeredClientRepository) {
		this(jdbcOperations, registeredClientRepository, new DefaultLobHandler());
	}

	/**
	 * Constructs a {@code JdbcOAuth2AuthorizationService} using the provided parameters.
	 * @param jdbcOperations the JDBC operations
	 * @param registeredClientRepository the registered client repository
	 * @param lobHandler the handler for large binary fields and large text fields
	 */
	public JdbcOAuth2AuthorizationService(JdbcOperations jdbcOperations,
			RegisteredClientRepository registeredClientRepository, LobHandler lobHandler) {
		Assert.notNull(jdbcOperations, "jdbcOperations cannot be null");
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(lobHandler, "lobHandler cannot be null");
		this.jdbcOperations = jdbcOperations;
		this.lobHandler = lobHandler;
		OAuth2AuthorizationRowMapper authorizationRowMapper = new OAuth2AuthorizationRowMapper(
				registeredClientRepository);
		authorizationRowMapper.setLobHandler(lobHandler);
		this.authorizationRowMapper = authorizationRowMapper;
		this.authorizationParametersMapper = new OAuth2AuthorizationParametersMapper();
		initColumnMetadata(jdbcOperations);
	}

	@Override
	public void save(OAuth2Authorization authorization) {
		Assert.notNull(authorization, "authorization cannot be null");
		OAuth2Authorization existingAuthorization = findById(authorization.getId());
		if (existingAuthorization == null) {
			insertAuthorization(authorization);
		}
		else {
			updateAuthorization(authorization);
		}
	}

	private void updateAuthorization(OAuth2Authorization authorization) {
		List<SqlParameterValue> parameters = this.authorizationParametersMapper.apply(authorization);
		SqlParameterValue id = parameters.remove(0);
		parameters.add(id);
		try (LobCreator lobCreator = this.lobHandler.getLobCreator()) {
			PreparedStatementSetter pss = new LobCreatorArgumentPreparedStatementSetter(lobCreator,
					parameters.toArray());
			this.jdbcOperations.update(UPDATE_AUTHORIZATION_SQL, pss);
		}
	}

	private void insertAuthorization(OAuth2Authorization authorization) {
		List<SqlParameterValue> parameters = this.authorizationParametersMapper.apply(authorization);
		try (LobCreator lobCreator = this.lobHandler.getLobCreator()) {
			PreparedStatementSetter pss = new LobCreatorArgumentPreparedStatementSetter(lobCreator,
					parameters.toArray());
			this.jdbcOperations.update(SAVE_AUTHORIZATION_SQL, pss);
		}
	}

	@Override
	public void remove(OAuth2Authorization authorization) {
		Assert.notNull(authorization, "authorization cannot be null");
		SqlParameterValue[] parameters = new SqlParameterValue[] {
				new SqlParameterValue(Types.VARCHAR, authorization.getId()) };
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters);
		this.jdbcOperations.update(REMOVE_AUTHORIZATION_SQL, pss);
	}

	@Nullable
	@Override
	public OAuth2Authorization findById(String id) {
		Assert.hasText(id, "id cannot be empty");
		List<SqlParameterValue> parameters = new ArrayList<>();
		parameters.add(new SqlParameterValue(Types.VARCHAR, id));
		return findBy(PK_FILTER, parameters);
	}

	@Nullable
	@Override
	public OAuth2Authorization findByToken(String token, @Nullable OAuth2TokenType tokenType) {
		Assert.hasText(token, "token cannot be empty");
		List<SqlParameterValue> parameters = new ArrayList<>();
		if (tokenType == null) {
			parameters.add(new SqlParameterValue(Types.VARCHAR, token));
			parameters.add(mapToSqlParameter(AUTHORIZATION_CODE_VALUE, token));
			parameters.add(mapToSqlParameter(ACCESS_TOKEN_VALUE, token));
			parameters.add(mapToSqlParameter(OIDC_ID_TOKEN_VALUE, token));
			parameters.add(mapToSqlParameter(REFRESH_TOKEN_VALUE, token));
			parameters.add(mapToSqlParameter(USER_CODE_VALUE, token));
			parameters.add(mapToSqlParameter(DEVICE_CODE_VALUE, token));
			return findBy(UNKNOWN_TOKEN_TYPE_FILTER, parameters);
		}
		else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
			parameters.add(new SqlParameterValue(Types.VARCHAR, token));
			return findBy(STATE_FILTER, parameters);
		}
		else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
			parameters.add(mapToSqlParameter(AUTHORIZATION_CODE_VALUE, token));
			return findBy(AUTHORIZATION_CODE_FILTER, parameters);
		}
		else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
			parameters.add(mapToSqlParameter(ACCESS_TOKEN_VALUE, token));
			return findBy(ACCESS_TOKEN_FILTER, parameters);
		}
		else if (OidcParameterNames.ID_TOKEN.equals(tokenType.getValue())) {
			parameters.add(mapToSqlParameter(OIDC_ID_TOKEN_VALUE, token));
			return findBy(ID_TOKEN_FILTER, parameters);
		}
		else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
			parameters.add(mapToSqlParameter(REFRESH_TOKEN_VALUE, token));
			return findBy(REFRESH_TOKEN_FILTER, parameters);
		}
		else if (OAuth2ParameterNames.USER_CODE.equals(tokenType.getValue())) {
			parameters.add(mapToSqlParameter(USER_CODE_VALUE, token));
			return findBy(USER_CODE_FILTER, parameters);
		}
		else if (OAuth2ParameterNames.DEVICE_CODE.equals(tokenType.getValue())) {
			parameters.add(mapToSqlParameter(DEVICE_CODE_VALUE, token));
			return findBy(DEVICE_CODE_FILTER, parameters);
		}
		return null;
	}

	private OAuth2Authorization findBy(String filter, List<SqlParameterValue> parameters) {
		try (LobCreator lobCreator = getLobHandler().getLobCreator()) {
			PreparedStatementSetter pss = new LobCreatorArgumentPreparedStatementSetter(lobCreator,
					parameters.toArray());
			List<OAuth2Authorization> result = getJdbcOperations().query(LOAD_AUTHORIZATION_SQL + filter, pss,
					getAuthorizationRowMapper());
			return !result.isEmpty() ? result.get(0) : null;
		}
	}

	/**
	 * Sets the {@link RowMapper} used for mapping the current row in
	 * {@code java.sql.ResultSet} to {@link OAuth2Authorization}. The default is
	 * {@link OAuth2AuthorizationRowMapper}.
	 * @param authorizationRowMapper the {@link RowMapper} used for mapping the current
	 * row in {@code ResultSet} to {@link OAuth2Authorization}
	 */
	public final void setAuthorizationRowMapper(RowMapper<OAuth2Authorization> authorizationRowMapper) {
		Assert.notNull(authorizationRowMapper, "authorizationRowMapper cannot be null");
		this.authorizationRowMapper = authorizationRowMapper;
	}

	/**
	 * Sets the {@code Function} used for mapping {@link OAuth2Authorization} to a
	 * {@code List} of {@link SqlParameterValue}. The default is
	 * {@link OAuth2AuthorizationParametersMapper}.
	 * @param authorizationParametersMapper the {@code Function} used for mapping
	 * {@link OAuth2Authorization} to a {@code List} of {@link SqlParameterValue}
	 */
	public final void setAuthorizationParametersMapper(
			Function<OAuth2Authorization, List<SqlParameterValue>> authorizationParametersMapper) {
		Assert.notNull(authorizationParametersMapper, "authorizationParametersMapper cannot be null");
		this.authorizationParametersMapper = authorizationParametersMapper;
	}

	protected final JdbcOperations getJdbcOperations() {
		return this.jdbcOperations;
	}

	protected final LobHandler getLobHandler() {
		return this.lobHandler;
	}

	protected final RowMapper<OAuth2Authorization> getAuthorizationRowMapper() {
		return this.authorizationRowMapper;
	}

	protected final Function<OAuth2Authorization, List<SqlParameterValue>> getAuthorizationParametersMapper() {
		return this.authorizationParametersMapper;
	}

	private static void initColumnMetadata(JdbcOperations jdbcOperations) {
		columnMetadataMap = new HashMap<>();
		ColumnMetadata columnMetadata;

		columnMetadata = getColumnMetadata(jdbcOperations, "attributes", Types.BLOB);
		columnMetadataMap.put(columnMetadata.getColumnName(), columnMetadata);
		columnMetadata = getColumnMetadata(jdbcOperations, AUTHORIZATION_CODE_VALUE, Types.BLOB);
		columnMetadataMap.put(columnMetadata.getColumnName(), columnMetadata);
		columnMetadata = getColumnMetadata(jdbcOperations, AUTHORIZATION_CODE_METADATA, Types.BLOB);
		columnMetadataMap.put(columnMetadata.getColumnName(), columnMetadata);
		columnMetadata = getColumnMetadata(jdbcOperations, ACCESS_TOKEN_VALUE, Types.BLOB);
		columnMetadataMap.put(columnMetadata.getColumnName(), columnMetadata);
		columnMetadata = getColumnMetadata(jdbcOperations, ACCESS_TOKEN_METADATA, Types.BLOB);
		columnMetadataMap.put(columnMetadata.getColumnName(), columnMetadata);
		columnMetadata = getColumnMetadata(jdbcOperations, OIDC_ID_TOKEN_VALUE, Types.BLOB);
		columnMetadataMap.put(columnMetadata.getColumnName(), columnMetadata);
		columnMetadata = getColumnMetadata(jdbcOperations, OIDC_ID_TOKEN_METADATA, Types.BLOB);
		columnMetadataMap.put(columnMetadata.getColumnName(), columnMetadata);
		columnMetadata = getColumnMetadata(jdbcOperations, REFRESH_TOKEN_VALUE, Types.BLOB);
		columnMetadataMap.put(columnMetadata.getColumnName(), columnMetadata);
		columnMetadata = getColumnMetadata(jdbcOperations, REFRESH_TOKEN_METADATA, Types.BLOB);
		columnMetadataMap.put(columnMetadata.getColumnName(), columnMetadata);
		columnMetadata = getColumnMetadata(jdbcOperations, USER_CODE_VALUE, Types.BLOB);
		columnMetadataMap.put(columnMetadata.getColumnName(), columnMetadata);
		columnMetadata = getColumnMetadata(jdbcOperations, USER_CODE_METADATA, Types.BLOB);
		columnMetadataMap.put(columnMetadata.getColumnName(), columnMetadata);
		columnMetadata = getColumnMetadata(jdbcOperations, DEVICE_CODE_VALUE, Types.BLOB);
		columnMetadataMap.put(columnMetadata.getColumnName(), columnMetadata);
		columnMetadata = getColumnMetadata(jdbcOperations, DEVICE_CODE_METADATA, Types.BLOB);
		columnMetadataMap.put(columnMetadata.getColumnName(), columnMetadata);
	}

	private static ColumnMetadata getColumnMetadata(JdbcOperations jdbcOperations, String columnName,
			int defaultDataType) {
		Integer dataType = jdbcOperations.execute((ConnectionCallback<Integer>) (conn) -> {
			DatabaseMetaData databaseMetaData = conn.getMetaData();
			ResultSet rs = databaseMetaData.getColumns(null, null, TABLE_NAME, columnName);
			if (rs.next()) {
				return rs.getInt("DATA_TYPE");
			}
			// NOTE: (Applies to HSQL)
			// When a database object is created with one of the CREATE statements or
			// renamed with the ALTER statement,
			// if the name is enclosed in double quotes, the exact name is used as the
			// case-normal form.
			// But if it is not enclosed in double quotes,
			// the name is converted to uppercase and this uppercase version is stored in
			// the database as the case-normal form.
			rs = databaseMetaData.getColumns(null, null, TABLE_NAME.toUpperCase(Locale.ENGLISH),
					columnName.toUpperCase(Locale.ENGLISH));
			if (rs.next()) {
				return rs.getInt("DATA_TYPE");
			}
			return null;
		});
		return new ColumnMetadata(columnName, (dataType != null) ? dataType : defaultDataType);
	}

	private static SqlParameterValue mapToSqlParameter(String columnName, String value) {
		ColumnMetadata columnMetadata = columnMetadataMap.get(columnName);
		return (Types.BLOB == columnMetadata.getDataType() && StringUtils.hasText(value))
				? new SqlParameterValue(Types.BLOB, value.getBytes(StandardCharsets.UTF_8))
				: new SqlParameterValue(columnMetadata.getDataType(), value);
	}

	/**
	 * The default {@link RowMapper} that maps the current row in
	 * {@code java.sql.ResultSet} to {@link OAuth2Authorization}.
	 */
	public static class OAuth2AuthorizationRowMapper implements RowMapper<OAuth2Authorization> {

		private final RegisteredClientRepository registeredClientRepository;

		private LobHandler lobHandler = new DefaultLobHandler();

		private ObjectMapper objectMapper = new ObjectMapper();

		public OAuth2AuthorizationRowMapper(RegisteredClientRepository registeredClientRepository) {
			Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
			this.registeredClientRepository = registeredClientRepository;

			ClassLoader classLoader = JdbcOAuth2AuthorizationService.class.getClassLoader();
			List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
			this.objectMapper.registerModules(securityModules);
			this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
		}

		@Override
		@SuppressWarnings("unchecked")
		public OAuth2Authorization mapRow(ResultSet rs, int rowNum) throws SQLException {
			String registeredClientId = rs.getString("registered_client_id");
			RegisteredClient registeredClient = this.registeredClientRepository.findById(registeredClientId);
			if (registeredClient == null) {
				throw new DataRetrievalFailureException("The RegisteredClient with id '" + registeredClientId
						+ "' was not found in the RegisteredClientRepository.");
			}

			OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient);
			String id = rs.getString("id");
			String principalName = rs.getString("principal_name");
			String authorizationGrantType = rs.getString("authorization_grant_type");
			Set<String> authorizedScopes = Collections.emptySet();
			String authorizedScopesString = rs.getString("authorized_scopes");
			if (authorizedScopesString != null) {
				authorizedScopes = StringUtils.commaDelimitedListToSet(authorizedScopesString);
			}
			Map<String, Object> attributes = parseMap(getLobValue(rs, "attributes"));

			builder.id(id)
				.principalName(principalName)
				.authorizationGrantType(new AuthorizationGrantType(authorizationGrantType))
				.authorizedScopes(authorizedScopes)
				.attributes((attrs) -> attrs.putAll(attributes));

			String state = rs.getString("state");
			if (StringUtils.hasText(state)) {
				builder.attribute(OAuth2ParameterNames.STATE, state);
			}

			Instant tokenIssuedAt;
			Instant tokenExpiresAt;
			String authorizationCodeValue = getLobValue(rs, AUTHORIZATION_CODE_VALUE);

			if (StringUtils.hasText(authorizationCodeValue)) {
				tokenIssuedAt = rs.getTimestamp("authorization_code_issued_at").toInstant();
				tokenExpiresAt = rs.getTimestamp("authorization_code_expires_at").toInstant();
				Map<String, Object> authorizationCodeMetadata = parseMap(getLobValue(rs, AUTHORIZATION_CODE_METADATA));

				OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(authorizationCodeValue,
						tokenIssuedAt, tokenExpiresAt);
				builder.token(authorizationCode, (metadata) -> metadata.putAll(authorizationCodeMetadata));
			}

			String accessTokenValue = getLobValue(rs, ACCESS_TOKEN_VALUE);
			if (StringUtils.hasText(accessTokenValue)) {
				tokenIssuedAt = rs.getTimestamp("access_token_issued_at").toInstant();
				tokenExpiresAt = rs.getTimestamp("access_token_expires_at").toInstant();
				Map<String, Object> accessTokenMetadata = parseMap(getLobValue(rs, ACCESS_TOKEN_METADATA));
				OAuth2AccessToken.TokenType tokenType = null;
				if (OAuth2AccessToken.TokenType.BEARER.getValue().equalsIgnoreCase(rs.getString("access_token_type"))) {
					tokenType = OAuth2AccessToken.TokenType.BEARER;
				}
				else if (OAuth2AccessToken.TokenType.DPOP.getValue()
					.equalsIgnoreCase(rs.getString("access_token_type"))) {
					tokenType = OAuth2AccessToken.TokenType.DPOP;
				}

				Set<String> scopes = Collections.emptySet();
				String accessTokenScopes = rs.getString("access_token_scopes");
				if (accessTokenScopes != null) {
					scopes = StringUtils.commaDelimitedListToSet(accessTokenScopes);
				}
				OAuth2AccessToken accessToken = new OAuth2AccessToken(tokenType, accessTokenValue, tokenIssuedAt,
						tokenExpiresAt, scopes);
				builder.token(accessToken, (metadata) -> metadata.putAll(accessTokenMetadata));
			}

			String oidcIdTokenValue = getLobValue(rs, OIDC_ID_TOKEN_VALUE);
			if (StringUtils.hasText(oidcIdTokenValue)) {
				tokenIssuedAt = rs.getTimestamp("oidc_id_token_issued_at").toInstant();
				tokenExpiresAt = rs.getTimestamp("oidc_id_token_expires_at").toInstant();
				Map<String, Object> oidcTokenMetadata = parseMap(getLobValue(rs, OIDC_ID_TOKEN_METADATA));

				OidcIdToken oidcToken = new OidcIdToken(oidcIdTokenValue, tokenIssuedAt, tokenExpiresAt,
						(Map<String, Object>) oidcTokenMetadata.get(OAuth2Authorization.Token.CLAIMS_METADATA_NAME));
				builder.token(oidcToken, (metadata) -> metadata.putAll(oidcTokenMetadata));
			}

			String refreshTokenValue = getLobValue(rs, REFRESH_TOKEN_VALUE);
			if (StringUtils.hasText(refreshTokenValue)) {
				tokenIssuedAt = rs.getTimestamp("refresh_token_issued_at").toInstant();
				tokenExpiresAt = null;
				Timestamp refreshTokenExpiresAt = rs.getTimestamp("refresh_token_expires_at");
				if (refreshTokenExpiresAt != null) {
					tokenExpiresAt = refreshTokenExpiresAt.toInstant();
				}
				Map<String, Object> refreshTokenMetadata = parseMap(getLobValue(rs, REFRESH_TOKEN_METADATA));

				OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(refreshTokenValue, tokenIssuedAt,
						tokenExpiresAt);
				builder.token(refreshToken, (metadata) -> metadata.putAll(refreshTokenMetadata));
			}

			String userCodeValue = getLobValue(rs, USER_CODE_VALUE);
			if (StringUtils.hasText(userCodeValue)) {
				tokenIssuedAt = rs.getTimestamp("user_code_issued_at").toInstant();
				tokenExpiresAt = rs.getTimestamp("user_code_expires_at").toInstant();
				Map<String, Object> userCodeMetadata = parseMap(getLobValue(rs, USER_CODE_METADATA));

				OAuth2UserCode userCode = new OAuth2UserCode(userCodeValue, tokenIssuedAt, tokenExpiresAt);
				builder.token(userCode, (metadata) -> metadata.putAll(userCodeMetadata));
			}

			String deviceCodeValue = getLobValue(rs, DEVICE_CODE_VALUE);
			if (StringUtils.hasText(deviceCodeValue)) {
				tokenIssuedAt = rs.getTimestamp("device_code_issued_at").toInstant();
				tokenExpiresAt = rs.getTimestamp("device_code_expires_at").toInstant();
				Map<String, Object> deviceCodeMetadata = parseMap(getLobValue(rs, DEVICE_CODE_METADATA));

				OAuth2DeviceCode deviceCode = new OAuth2DeviceCode(deviceCodeValue, tokenIssuedAt, tokenExpiresAt);
				builder.token(deviceCode, (metadata) -> metadata.putAll(deviceCodeMetadata));
			}

			return builder.build();
		}

		private String getLobValue(ResultSet rs, String columnName) throws SQLException {
			String columnValue = null;
			ColumnMetadata columnMetadata = columnMetadataMap.get(columnName);
			if (Types.BLOB == columnMetadata.getDataType()) {
				byte[] columnValueBytes = this.lobHandler.getBlobAsBytes(rs, columnName);
				if (columnValueBytes != null) {
					columnValue = new String(columnValueBytes, StandardCharsets.UTF_8);
				}
			}
			else if (Types.CLOB == columnMetadata.getDataType()) {
				columnValue = this.lobHandler.getClobAsString(rs, columnName);
			}
			else {
				columnValue = rs.getString(columnName);
			}
			return columnValue;
		}

		public final void setLobHandler(LobHandler lobHandler) {
			Assert.notNull(lobHandler, "lobHandler cannot be null");
			this.lobHandler = lobHandler;
		}

		public final void setObjectMapper(ObjectMapper objectMapper) {
			Assert.notNull(objectMapper, "objectMapper cannot be null");
			this.objectMapper = objectMapper;
		}

		protected final RegisteredClientRepository getRegisteredClientRepository() {
			return this.registeredClientRepository;
		}

		protected final LobHandler getLobHandler() {
			return this.lobHandler;
		}

		protected final ObjectMapper getObjectMapper() {
			return this.objectMapper;
		}

		private Map<String, Object> parseMap(String data) {
			try {
				return this.objectMapper.readValue(data, new TypeReference<>() {
				});
			}
			catch (Exception ex) {
				throw new IllegalArgumentException(ex.getMessage(), ex);
			}
		}

	}

	/**
	 * The default {@code Function} that maps {@link OAuth2Authorization} to a
	 * {@code List} of {@link SqlParameterValue}.
	 */
	public static class OAuth2AuthorizationParametersMapper
			implements Function<OAuth2Authorization, List<SqlParameterValue>> {

		private ObjectMapper objectMapper = new ObjectMapper();

		public OAuth2AuthorizationParametersMapper() {
			ClassLoader classLoader = JdbcOAuth2AuthorizationService.class.getClassLoader();
			List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
			this.objectMapper.registerModules(securityModules);
			this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
		}

		@Override
		public List<SqlParameterValue> apply(OAuth2Authorization authorization) {
			List<SqlParameterValue> parameters = new ArrayList<>();
			parameters.add(new SqlParameterValue(Types.VARCHAR, authorization.getId()));
			parameters.add(new SqlParameterValue(Types.VARCHAR, authorization.getRegisteredClientId()));
			parameters.add(new SqlParameterValue(Types.VARCHAR, authorization.getPrincipalName()));
			parameters.add(new SqlParameterValue(Types.VARCHAR, authorization.getAuthorizationGrantType().getValue()));

			String authorizedScopes = null;
			if (!CollectionUtils.isEmpty(authorization.getAuthorizedScopes())) {
				authorizedScopes = StringUtils.collectionToDelimitedString(authorization.getAuthorizedScopes(), ",");
			}
			parameters.add(new SqlParameterValue(Types.VARCHAR, authorizedScopes));

			String attributes = writeMap(authorization.getAttributes());
			parameters.add(mapToSqlParameter("attributes", attributes));

			String state = null;
			String authorizationState = authorization.getAttribute(OAuth2ParameterNames.STATE);
			if (StringUtils.hasText(authorizationState)) {
				state = authorizationState;
			}
			parameters.add(new SqlParameterValue(Types.VARCHAR, state));

			OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = authorization
				.getToken(OAuth2AuthorizationCode.class);
			List<SqlParameterValue> authorizationCodeSqlParameters = toSqlParameterList(AUTHORIZATION_CODE_VALUE,
					AUTHORIZATION_CODE_METADATA, authorizationCode);
			parameters.addAll(authorizationCodeSqlParameters);

			OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getToken(OAuth2AccessToken.class);
			List<SqlParameterValue> accessTokenSqlParameters = toSqlParameterList(ACCESS_TOKEN_VALUE,
					ACCESS_TOKEN_METADATA, accessToken);
			parameters.addAll(accessTokenSqlParameters);
			String accessTokenType = null;
			String accessTokenScopes = null;
			if (accessToken != null) {
				accessTokenType = accessToken.getToken().getTokenType().getValue();
				if (!CollectionUtils.isEmpty(accessToken.getToken().getScopes())) {
					accessTokenScopes = StringUtils.collectionToDelimitedString(accessToken.getToken().getScopes(),
							",");
				}
			}
			parameters.add(new SqlParameterValue(Types.VARCHAR, accessTokenType));
			parameters.add(new SqlParameterValue(Types.VARCHAR, accessTokenScopes));

			OAuth2Authorization.Token<OidcIdToken> oidcIdToken = authorization.getToken(OidcIdToken.class);
			List<SqlParameterValue> oidcIdTokenSqlParameters = toSqlParameterList(OIDC_ID_TOKEN_VALUE,
					OIDC_ID_TOKEN_METADATA, oidcIdToken);
			parameters.addAll(oidcIdTokenSqlParameters);

			OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();
			List<SqlParameterValue> refreshTokenSqlParameters = toSqlParameterList(REFRESH_TOKEN_VALUE,
					REFRESH_TOKEN_METADATA, refreshToken);
			parameters.addAll(refreshTokenSqlParameters);

			OAuth2Authorization.Token<OAuth2UserCode> userCode = authorization.getToken(OAuth2UserCode.class);
			List<SqlParameterValue> userCodeSqlParameters = toSqlParameterList(USER_CODE_VALUE, USER_CODE_METADATA,
					userCode);
			parameters.addAll(userCodeSqlParameters);

			OAuth2Authorization.Token<OAuth2DeviceCode> deviceCode = authorization.getToken(OAuth2DeviceCode.class);
			List<SqlParameterValue> deviceCodeSqlParameters = toSqlParameterList(DEVICE_CODE_VALUE,
					DEVICE_CODE_METADATA, deviceCode);
			parameters.addAll(deviceCodeSqlParameters);

			return parameters;
		}

		public final void setObjectMapper(ObjectMapper objectMapper) {
			Assert.notNull(objectMapper, "objectMapper cannot be null");
			this.objectMapper = objectMapper;
		}

		protected final ObjectMapper getObjectMapper() {
			return this.objectMapper;
		}

		private <T extends OAuth2Token> List<SqlParameterValue> toSqlParameterList(String tokenColumnName,
				String tokenMetadataColumnName, OAuth2Authorization.Token<T> token) {

			List<SqlParameterValue> parameters = new ArrayList<>();
			String tokenValue = null;
			Timestamp tokenIssuedAt = null;
			Timestamp tokenExpiresAt = null;
			String metadata = null;
			if (token != null) {
				tokenValue = token.getToken().getTokenValue();
				if (token.getToken().getIssuedAt() != null) {
					tokenIssuedAt = Timestamp.from(token.getToken().getIssuedAt());
				}
				if (token.getToken().getExpiresAt() != null) {
					tokenExpiresAt = Timestamp.from(token.getToken().getExpiresAt());
				}
				metadata = writeMap(token.getMetadata());
			}

			parameters.add(mapToSqlParameter(tokenColumnName, tokenValue));
			parameters.add(new SqlParameterValue(Types.TIMESTAMP, tokenIssuedAt));
			parameters.add(new SqlParameterValue(Types.TIMESTAMP, tokenExpiresAt));
			parameters.add(mapToSqlParameter(tokenMetadataColumnName, metadata));
			return parameters;
		}

		private String writeMap(Map<String, Object> data) {
			try {
				return this.objectMapper.writeValueAsString(data);
			}
			catch (Exception ex) {
				throw new IllegalArgumentException(ex.getMessage(), ex);
			}
		}

	}

	private static final class LobCreatorArgumentPreparedStatementSetter extends ArgumentPreparedStatementSetter {

		private final LobCreator lobCreator;

		private LobCreatorArgumentPreparedStatementSetter(LobCreator lobCreator, Object[] args) {
			super(args);
			this.lobCreator = lobCreator;
		}

		@Override
		protected void doSetValue(PreparedStatement ps, int parameterPosition, Object argValue) throws SQLException {
			if (argValue instanceof SqlParameterValue paramValue) {
				if (paramValue.getSqlType() == Types.BLOB) {
					if (paramValue.getValue() != null) {
						Assert.isInstanceOf(byte[].class, paramValue.getValue(),
								"Value of blob parameter must be byte[]");
					}
					byte[] valueBytes = (byte[]) paramValue.getValue();
					this.lobCreator.setBlobAsBytes(ps, parameterPosition, valueBytes);
					return;
				}
				if (paramValue.getSqlType() == Types.CLOB) {
					if (paramValue.getValue() != null) {
						Assert.isInstanceOf(String.class, paramValue.getValue(),
								"Value of clob parameter must be String");
					}
					String valueString = (String) paramValue.getValue();
					this.lobCreator.setClobAsString(ps, parameterPosition, valueString);
					return;
				}
			}
			super.doSetValue(ps, parameterPosition, argValue);
		}

	}

	private static final class ColumnMetadata {

		private final String columnName;

		private final int dataType;

		private ColumnMetadata(String columnName, int dataType) {
			this.columnName = columnName;
			this.dataType = dataType;
		}

		private String getColumnName() {
			return this.columnName;
		}

		private int getDataType() {
			return this.dataType;
		}

	}

	static class JdbcOAuth2AuthorizationServiceRuntimeHintsRegistrar implements RuntimeHintsRegistrar {

		@Override
		public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
			hints.resources()
				.registerResource(new ClassPathResource(
						"org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql"));
		}

	}

}
