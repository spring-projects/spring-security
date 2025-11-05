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

package org.springframework.security.oauth2.server.authorization.client;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import tools.jackson.databind.JacksonModule;
import tools.jackson.databind.json.JsonMapper;

import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.context.annotation.ImportRuntimeHints;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.ArgumentPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.SqlParameterValue;
import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.ConfigurationSettingNames;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * A JDBC implementation of a {@link RegisteredClientRepository} that uses a
 * {@link JdbcOperations} for {@link RegisteredClient} persistence.
 *
 * <p>
 * <b>IMPORTANT:</b> This {@code RegisteredClientRepository} depends on the table
 * definition described in
 * "classpath:org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql"
 * and therefore MUST be defined in the database schema.
 *
 * <p>
 * <b>NOTE:</b> This {@code RegisteredClientRepository} is a simplified JDBC
 * implementation that MAY be used in a production environment. However, it does have
 * limitations as it likely won't perform well in an environment requiring high
 * throughput. The expectation is that the consuming application will provide their own
 * implementation of {@code RegisteredClientRepository} that meets the performance
 * requirements for its deployment environment.
 *
 * @author Rafal Lewczuk
 * @author Joe Grandja
 * @author Ovidiu Popa
 * @author Josh Long
 * @since 7.0
 * @see RegisteredClientRepository
 * @see RegisteredClient
 * @see JdbcOperations
 * @see RowMapper
 */
@ImportRuntimeHints(JdbcRegisteredClientRepository.JdbcRegisteredClientRepositoryRuntimeHintsRegistrar.class)
public class JdbcRegisteredClientRepository implements RegisteredClientRepository {

	// @formatter:off
	private static final String COLUMN_NAMES = "id, "
			+ "client_id, "
			+ "client_id_issued_at, "
			+ "client_secret, "
			+ "client_secret_expires_at, "
			+ "client_name, "
			+ "client_authentication_methods, "
			+ "authorization_grant_types, "
			+ "redirect_uris, "
			+ "post_logout_redirect_uris, "
			+ "scopes, "
			+ "client_settings,"
			+ "token_settings";
	// @formatter:on

	private static final String TABLE_NAME = "oauth2_registered_client";

	private static final String PK_FILTER = "id = ?";

	private static final String LOAD_REGISTERED_CLIENT_SQL = "SELECT " + COLUMN_NAMES + " FROM " + TABLE_NAME
			+ " WHERE ";

	// @formatter:off
	private static final String INSERT_REGISTERED_CLIENT_SQL = "INSERT INTO " + TABLE_NAME
			+ "(" + COLUMN_NAMES + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
	// @formatter:on

	// @formatter:off
	private static final String UPDATE_REGISTERED_CLIENT_SQL = "UPDATE " + TABLE_NAME
			+ " SET client_secret = ?, client_secret_expires_at = ?, client_name = ?, client_authentication_methods = ?,"
			+ " authorization_grant_types = ?, redirect_uris = ?, post_logout_redirect_uris = ?, scopes = ?,"
			+ " client_settings = ?, token_settings = ?"
			+ " WHERE " + PK_FILTER;
	// @formatter:on

	private static final String COUNT_REGISTERED_CLIENT_SQL = "SELECT COUNT(*) FROM " + TABLE_NAME + " WHERE ";

	private final JdbcOperations jdbcOperations;

	private RowMapper<RegisteredClient> registeredClientRowMapper;

	private Function<RegisteredClient, List<SqlParameterValue>> registeredClientParametersMapper;

	/**
	 * Constructs a {@code JdbcRegisteredClientRepository} using the provided parameters.
	 * @param jdbcOperations the JDBC operations
	 */
	public JdbcRegisteredClientRepository(JdbcOperations jdbcOperations) {
		Assert.notNull(jdbcOperations, "jdbcOperations cannot be null");
		this.jdbcOperations = jdbcOperations;
		this.registeredClientRowMapper = new JsonMapperRegisteredClientRowMapper();
		this.registeredClientParametersMapper = new JsonMapperRegisteredClientParametersMapper();
	}

	@Override
	public void save(RegisteredClient registeredClient) {
		Assert.notNull(registeredClient, "registeredClient cannot be null");
		RegisteredClient existingRegisteredClient = findBy(PK_FILTER, registeredClient.getId());
		if (existingRegisteredClient != null) {
			updateRegisteredClient(registeredClient);
		}
		else {
			insertRegisteredClient(registeredClient);
		}
	}

	private void updateRegisteredClient(RegisteredClient registeredClient) {
		List<SqlParameterValue> parameters = new ArrayList<>(
				this.registeredClientParametersMapper.apply(registeredClient));
		SqlParameterValue id = parameters.remove(0);
		parameters.remove(0); // remove client_id
		parameters.remove(0); // remove client_id_issued_at
		parameters.add(id);
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());
		this.jdbcOperations.update(UPDATE_REGISTERED_CLIENT_SQL, pss);
	}

	private void insertRegisteredClient(RegisteredClient registeredClient) {
		assertUniqueIdentifiers(registeredClient);
		List<SqlParameterValue> parameters = this.registeredClientParametersMapper.apply(registeredClient);
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());
		this.jdbcOperations.update(INSERT_REGISTERED_CLIENT_SQL, pss);
	}

	private void assertUniqueIdentifiers(RegisteredClient registeredClient) {
		Integer count = this.jdbcOperations.queryForObject(COUNT_REGISTERED_CLIENT_SQL + "client_id = ?", Integer.class,
				registeredClient.getClientId());
		if (count != null && count > 0) {
			throw new IllegalArgumentException("Registered client must be unique. "
					+ "Found duplicate client identifier: " + registeredClient.getClientId());
		}
		if (StringUtils.hasText(registeredClient.getClientSecret())) {
			count = this.jdbcOperations.queryForObject(COUNT_REGISTERED_CLIENT_SQL + "client_secret = ?", Integer.class,
					registeredClient.getClientSecret());
			if (count != null && count > 0) {
				throw new IllegalArgumentException("Registered client must be unique. "
						+ "Found duplicate client secret for identifier: " + registeredClient.getId());
			}
		}
	}

	@Override
	public RegisteredClient findById(String id) {
		Assert.hasText(id, "id cannot be empty");
		return findBy("id = ?", id);
	}

	@Override
	public RegisteredClient findByClientId(String clientId) {
		Assert.hasText(clientId, "clientId cannot be empty");
		return findBy("client_id = ?", clientId);
	}

	private RegisteredClient findBy(String filter, Object... args) {
		List<RegisteredClient> result = this.jdbcOperations.query(LOAD_REGISTERED_CLIENT_SQL + filter,
				this.registeredClientRowMapper, args);
		return !result.isEmpty() ? result.get(0) : null;
	}

	/**
	 * Sets the {@link RowMapper} used for mapping the current row in
	 * {@code java.sql.ResultSet} to {@link RegisteredClient}. The default is
	 * {@link JsonMapperRegisteredClientRowMapper}.
	 * @param registeredClientRowMapper the {@link RowMapper} used for mapping the current
	 * row in {@code ResultSet} to {@link RegisteredClient}
	 */
	public final void setRegisteredClientRowMapper(RowMapper<RegisteredClient> registeredClientRowMapper) {
		Assert.notNull(registeredClientRowMapper, "registeredClientRowMapper cannot be null");
		this.registeredClientRowMapper = registeredClientRowMapper;
	}

	/**
	 * Sets the {@code Function} used for mapping {@link RegisteredClient} to a
	 * {@code List} of {@link SqlParameterValue}. The default is
	 * {@link JsonMapperRegisteredClientParametersMapper}.
	 * @param registeredClientParametersMapper the {@code Function} used for mapping
	 * {@link RegisteredClient} to a {@code List} of {@link SqlParameterValue}
	 */
	public final void setRegisteredClientParametersMapper(
			Function<RegisteredClient, List<SqlParameterValue>> registeredClientParametersMapper) {
		Assert.notNull(registeredClientParametersMapper, "registeredClientParametersMapper cannot be null");
		this.registeredClientParametersMapper = registeredClientParametersMapper;
	}

	protected final JdbcOperations getJdbcOperations() {
		return this.jdbcOperations;
	}

	protected final RowMapper<RegisteredClient> getRegisteredClientRowMapper() {
		return this.registeredClientRowMapper;
	}

	protected final Function<RegisteredClient, List<SqlParameterValue>> getRegisteredClientParametersMapper() {
		return this.registeredClientParametersMapper;
	}

	/**
	 * The default {@link RowMapper} that maps the current row in
	 * {@code java.sql.ResultSet} to {@link RegisteredClient} using Jackson 3's
	 * {@link JsonMapper}.
	 *
	 * @author Joe Grandja
	 * @since 7.0
	 */
	public static class JsonMapperRegisteredClientRowMapper extends AbstractRegisteredClientRowMapper {

		private final JsonMapper jsonMapper;

		public JsonMapperRegisteredClientRowMapper() {
			this(Jackson3.createJsonMapper());
		}

		public JsonMapperRegisteredClientRowMapper(JsonMapper jsonMapper) {
			Assert.notNull(jsonMapper, "jsonMapper cannot be null");
			this.jsonMapper = jsonMapper;
		}

		@Override
		Map<String, Object> readValue(String data) {
			final ParameterizedTypeReference<Map<String, Object>> typeReference = new ParameterizedTypeReference<>() {
			};
			tools.jackson.databind.JavaType javaType = this.jsonMapper.getTypeFactory()
				.constructType(typeReference.getType());
			return this.jsonMapper.readValue(data, javaType);
		}

	}

	/**
	 * A {@link RowMapper} that maps the current row in {@code java.sql.ResultSet} to
	 * {@link RegisteredClient} using Jackson 2's {@link ObjectMapper}.
	 *
	 * @deprecated Use {@link JsonMapperRegisteredClientRowMapper} to switch to Jackson 3.
	 */
	@Deprecated(forRemoval = true, since = "7.0")
	public static class RegisteredClientRowMapper extends AbstractRegisteredClientRowMapper {

		private ObjectMapper objectMapper = Jackson2.createObjectMapper();

		public final void setObjectMapper(ObjectMapper objectMapper) {
			Assert.notNull(objectMapper, "objectMapper cannot be null");
			this.objectMapper = objectMapper;
		}

		protected final ObjectMapper getObjectMapper() {
			return this.objectMapper;
		}

		@Override
		Map<String, Object> readValue(String data) throws JsonProcessingException {
			final ParameterizedTypeReference<Map<String, Object>> typeReference = new ParameterizedTypeReference<>() {
			};
			com.fasterxml.jackson.databind.JavaType javaType = this.objectMapper.getTypeFactory()
				.constructType(typeReference.getType());
			return this.objectMapper.readValue(data, javaType);
		}

	}

	/**
	 * The base {@link RowMapper} that maps the current row in {@code java.sql.ResultSet}
	 * to {@link RegisteredClient}. This is extracted to a distinct class so that
	 * {@link RegisteredClientRowMapper} can be deprecated in favor of
	 * {@link JsonMapperRegisteredClientRowMapper}.
	 */
	private abstract static class AbstractRegisteredClientRowMapper implements RowMapper<RegisteredClient> {

		private AbstractRegisteredClientRowMapper() {
		}

		@Override
		public RegisteredClient mapRow(ResultSet rs, int rowNum) throws SQLException {
			Timestamp clientIdIssuedAt = rs.getTimestamp("client_id_issued_at");
			Timestamp clientSecretExpiresAt = rs.getTimestamp("client_secret_expires_at");
			Set<String> clientAuthenticationMethods = StringUtils
				.commaDelimitedListToSet(rs.getString("client_authentication_methods"));
			Set<String> authorizationGrantTypes = StringUtils
				.commaDelimitedListToSet(rs.getString("authorization_grant_types"));
			Set<String> redirectUris = StringUtils.commaDelimitedListToSet(rs.getString("redirect_uris"));
			Set<String> postLogoutRedirectUris = StringUtils
				.commaDelimitedListToSet(rs.getString("post_logout_redirect_uris"));
			Set<String> clientScopes = StringUtils.commaDelimitedListToSet(rs.getString("scopes"));

			// @formatter:off
			RegisteredClient.Builder builder = RegisteredClient.withId(rs.getString("id"))
					.clientId(rs.getString("client_id"))
					.clientIdIssuedAt((clientIdIssuedAt != null) ? clientIdIssuedAt.toInstant() : null)
					.clientSecret(rs.getString("client_secret"))
					.clientSecretExpiresAt((clientSecretExpiresAt != null) ? clientSecretExpiresAt.toInstant() : null)
					.clientName(rs.getString("client_name"))
					.clientAuthenticationMethods((authenticationMethods) ->
							clientAuthenticationMethods.forEach((authenticationMethod) ->
									authenticationMethods.add(resolveClientAuthenticationMethod(authenticationMethod))))
					.authorizationGrantTypes((grantTypes) ->
							authorizationGrantTypes.forEach((grantType) ->
									grantTypes.add(resolveAuthorizationGrantType(grantType))))
					.redirectUris((uris) -> uris.addAll(redirectUris))
					.postLogoutRedirectUris((uris) -> uris.addAll(postLogoutRedirectUris))
					.scopes((scopes) -> scopes.addAll(clientScopes));
			// @formatter:on

			Map<String, Object> clientSettingsMap = parseMap(rs.getString("client_settings"));
			builder.clientSettings(ClientSettings.withSettings(clientSettingsMap).build());

			Map<String, Object> tokenSettingsMap = parseMap(rs.getString("token_settings"));
			TokenSettings.Builder tokenSettingsBuilder = TokenSettings.withSettings(tokenSettingsMap);
			if (!tokenSettingsMap.containsKey(ConfigurationSettingNames.Token.ACCESS_TOKEN_FORMAT)) {
				tokenSettingsBuilder.accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED);
			}
			builder.tokenSettings(tokenSettingsBuilder.build());

			return builder.build();
		}

		private Map<String, Object> parseMap(String data) {
			try {
				return readValue(data);
			}
			catch (Exception ex) {
				throw new IllegalArgumentException(ex.getMessage(), ex);
			}
		}

		abstract Map<String, Object> readValue(String data) throws Exception;

		private static AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
			if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
				return AuthorizationGrantType.AUTHORIZATION_CODE;
			}
			else if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)) {
				return AuthorizationGrantType.CLIENT_CREDENTIALS;
			}
			else if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
				return AuthorizationGrantType.REFRESH_TOKEN;
			}
			// Custom authorization grant type
			return new AuthorizationGrantType(authorizationGrantType);
		}

		private static ClientAuthenticationMethod resolveClientAuthenticationMethod(String clientAuthenticationMethod) {
			if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue().equals(clientAuthenticationMethod)) {
				return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
			}
			else if (ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue().equals(clientAuthenticationMethod)) {
				return ClientAuthenticationMethod.CLIENT_SECRET_POST;
			}
			else if (ClientAuthenticationMethod.NONE.getValue().equals(clientAuthenticationMethod)) {
				return ClientAuthenticationMethod.NONE;
			}
			// Custom client authentication method
			return new ClientAuthenticationMethod(clientAuthenticationMethod);
		}

	}

	/**
	 * The default {@code Function} that maps {@link RegisteredClient} to a {@code List}
	 * of {@link SqlParameterValue} using an instance of Jackson 3's {@link JsonMapper}.
	 */
	public static class JsonMapperRegisteredClientParametersMapper extends AbstractRegisteredClientParametersMapper {

		private final JsonMapper jsonMapper;

		public JsonMapperRegisteredClientParametersMapper() {
			this(Jackson3.createJsonMapper());
		}

		public JsonMapperRegisteredClientParametersMapper(JsonMapper jsonMapper) {
			Assert.notNull(jsonMapper, "jsonMapper cannot be null");
			this.jsonMapper = jsonMapper;
		}

		@Override
		String writeValueAsString(Map<String, Object> data) throws Exception {
			return this.jsonMapper.writeValueAsString(data);
		}

	}

	/**
	 * A {@code Function} that maps {@link RegisteredClient} to a {@code List} of
	 * {@link SqlParameterValue} using an instance of Jackson 2's {@link ObjectMapper}.
	 *
	 * @deprecated Use {@link JsonMapperRegisteredClientParametersMapper} to switch to
	 * Jackson 3.
	 */
	@Deprecated(forRemoval = true, since = "7.0")
	public static class RegisteredClientParametersMapper extends AbstractRegisteredClientParametersMapper {

		private ObjectMapper objectMapper = Jackson2.createObjectMapper();

		public final void setObjectMapper(ObjectMapper objectMapper) {
			Assert.notNull(objectMapper, "objectMapper cannot be null");
			this.objectMapper = objectMapper;
		}

		protected final ObjectMapper getObjectMapper() {
			return this.objectMapper;
		}

		@Override
		String writeValueAsString(Map<String, Object> data) throws JsonProcessingException {
			return this.objectMapper.writeValueAsString(data);
		}

	}

	/**
	 * The base {@code Function} that maps {@link RegisteredClient} to a {@code List} of
	 * {@link SqlParameterValue}.
	 */
	private abstract static class AbstractRegisteredClientParametersMapper
			implements Function<RegisteredClient, List<SqlParameterValue>> {

		private AbstractRegisteredClientParametersMapper() {
		}

		@Override
		public List<SqlParameterValue> apply(RegisteredClient registeredClient) {
			Timestamp clientIdIssuedAt = (registeredClient.getClientIdIssuedAt() != null)
					? Timestamp.from(registeredClient.getClientIdIssuedAt()) : Timestamp.from(Instant.now());

			Timestamp clientSecretExpiresAt = (registeredClient.getClientSecretExpiresAt() != null)
					? Timestamp.from(registeredClient.getClientSecretExpiresAt()) : null;

			List<String> clientAuthenticationMethods = new ArrayList<>(
					registeredClient.getClientAuthenticationMethods().size());
			registeredClient.getClientAuthenticationMethods()
				.forEach((clientAuthenticationMethod) -> clientAuthenticationMethods
					.add(clientAuthenticationMethod.getValue()));

			List<String> authorizationGrantTypes = new ArrayList<>(
					registeredClient.getAuthorizationGrantTypes().size());
			registeredClient.getAuthorizationGrantTypes()
				.forEach((authorizationGrantType) -> authorizationGrantTypes.add(authorizationGrantType.getValue()));

			return Arrays.asList(new SqlParameterValue(Types.VARCHAR, registeredClient.getId()),
					new SqlParameterValue(Types.VARCHAR, registeredClient.getClientId()),
					new SqlParameterValue(Types.TIMESTAMP, clientIdIssuedAt),
					new SqlParameterValue(Types.VARCHAR, registeredClient.getClientSecret()),
					new SqlParameterValue(Types.TIMESTAMP, clientSecretExpiresAt),
					new SqlParameterValue(Types.VARCHAR, registeredClient.getClientName()),
					new SqlParameterValue(Types.VARCHAR,
							StringUtils.collectionToCommaDelimitedString(clientAuthenticationMethods)),
					new SqlParameterValue(Types.VARCHAR,
							StringUtils.collectionToCommaDelimitedString(authorizationGrantTypes)),
					new SqlParameterValue(Types.VARCHAR,
							StringUtils.collectionToCommaDelimitedString(registeredClient.getRedirectUris())),
					new SqlParameterValue(Types.VARCHAR,
							StringUtils.collectionToCommaDelimitedString(registeredClient.getPostLogoutRedirectUris())),
					new SqlParameterValue(Types.VARCHAR,
							StringUtils.collectionToCommaDelimitedString(registeredClient.getScopes())),
					new SqlParameterValue(Types.VARCHAR, writeMap(registeredClient.getClientSettings().getSettings())),
					new SqlParameterValue(Types.VARCHAR, writeMap(registeredClient.getTokenSettings().getSettings())));
		}

		private String writeMap(Map<String, Object> data) {
			try {
				return writeValueAsString(data);
			}
			catch (Exception ex) {
				throw new IllegalArgumentException(ex.getMessage(), ex);
			}
		}

		abstract String writeValueAsString(Map<String, Object> data) throws Exception;

	}

	/**
	 * Nested class to protect from getting {@link NoClassDefFoundError} when Jackson 2 is
	 * not on the classpath.
	 *
	 * @deprecated This is used to allow transition to Jackson 3. Use {@link Jackson3}
	 * instead.
	 */
	@Deprecated(forRemoval = true, since = "7.0")
	private static final class Jackson2 {

		private static ObjectMapper createObjectMapper() {
			ObjectMapper objectMapper = new ObjectMapper();
			ClassLoader classLoader = Jackson2.class.getClassLoader();
			List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
			objectMapper.registerModules(securityModules);
			objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
			return objectMapper;
		}

	}

	/**
	 * Nested class used to get a common default instance of {@link JsonMapper}. It is in
	 * a nested class to protect from getting {@link NoClassDefFoundError} when Jackson 3
	 * is not on the classpath.
	 */
	private static final class Jackson3 {

		private static JsonMapper createJsonMapper() {
			List<JacksonModule> modules = SecurityJacksonModules.getModules(Jackson3.class.getClassLoader());
			return JsonMapper.builder().addModules(modules).build();
		}

	}

	static class JdbcRegisteredClientRepositoryRuntimeHintsRegistrar implements RuntimeHintsRegistrar {

		@Override
		public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
			hints.resources()
				.registerResource(new ClassPathResource(
						"org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql"));
		}

	}

}
