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
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.jdbc.core.ArgumentPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.SqlParameterValue;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository.RegisteredClientParametersMapper;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository.RegisteredClientRowMapper;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.util.StringUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link JdbcRegisteredClientRepository}.
 *
 * @author Rafal Lewczuk
 * @author Steve Riesenberg
 * @author Joe Grandja
 * @author Ovidiu Popa
 */
public class JdbcRegisteredClientRepositoryTests {

	private static final String OAUTH2_REGISTERED_CLIENT_SCHEMA_SQL_RESOURCE = "/org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql";

	private static final String OAUTH2_CUSTOM_REGISTERED_CLIENT_SCHEMA_SQL_RESOURCE = "/org/springframework/security/oauth2/server/authorization/client/custom-oauth2-registered-client-schema.sql";

	private EmbeddedDatabase db;

	private JdbcOperations jdbcOperations;

	private JdbcRegisteredClientRepository registeredClientRepository;

	@BeforeEach
	public void setUp() {
		this.db = createDb(OAUTH2_REGISTERED_CLIENT_SCHEMA_SQL_RESOURCE);
		this.jdbcOperations = new JdbcTemplate(this.db);
		this.registeredClientRepository = new JdbcRegisteredClientRepository(this.jdbcOperations);
	}

	@AfterEach
	public void tearDown() {
		this.db.shutdown();
	}

	@Test
	public void constructorWhenJdbcOperationsIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new JdbcRegisteredClientRepository(null))
				.withMessage("jdbcOperations cannot be null");
		// @formatter:on
	}

	@Test
	public void setRegisteredClientRowMapperWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.registeredClientRepository.setRegisteredClientRowMapper(null))
				.withMessage("registeredClientRowMapper cannot be null");
		// @formatter:on
	}

	@Test
	public void setRegisteredClientParametersMapperWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.registeredClientRepository.setRegisteredClientParametersMapper(null))
				.withMessage("registeredClientParametersMapper cannot be null");
		// @formatter:on
	}

	@Test
	public void saveWhenRegisteredClientNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.registeredClientRepository.save(null))
			.withMessageContaining("registeredClient cannot be null");
	}

	@Test
	public void saveWhenRegisteredClientExistsThenUpdated() {
		RegisteredClient originalRegisteredClient = TestRegisteredClients.registeredClient().build();
		this.registeredClientRepository.save(originalRegisteredClient);

		RegisteredClient registeredClient = this.registeredClientRepository.findById(originalRegisteredClient.getId());
		assertThat(registeredClient).isEqualTo(originalRegisteredClient);

		RegisteredClient updatedRegisteredClient = RegisteredClient.from(originalRegisteredClient)
			.clientId("test")
			.clientIdIssuedAt(Instant.now())
			.clientName("clientName")
			.scope("scope2")
			.build();

		RegisteredClient expectedUpdatedRegisteredClient = RegisteredClient.from(originalRegisteredClient)
			.clientName("clientName")
			.scope("scope2")
			.build();
		this.registeredClientRepository.save(updatedRegisteredClient);

		registeredClient = this.registeredClientRepository.findById(updatedRegisteredClient.getId());
		assertThat(registeredClient).isEqualTo(expectedUpdatedRegisteredClient);
		assertThat(registeredClient).isNotEqualTo(originalRegisteredClient);
	}

	@Test
	public void saveWhenNewThenSaved() {
		RegisteredClient expectedRegisteredClient = TestRegisteredClients.registeredClient()
			.clientSettings(
					ClientSettings.builder().tokenEndpointAuthenticationSigningAlgorithm(MacAlgorithm.HS256).build())
			.build();
		this.registeredClientRepository.save(expectedRegisteredClient);
		RegisteredClient registeredClient = this.registeredClientRepository.findById(expectedRegisteredClient.getId());
		assertThat(registeredClient).isEqualTo(expectedRegisteredClient);
	}

	@Test
	public void saveWhenClientSecretNullThenSaved() {
		RegisteredClient expectedRegisteredClient = TestRegisteredClients.registeredClient().clientSecret(null).build();
		this.registeredClientRepository.save(expectedRegisteredClient);
		RegisteredClient registeredClient = this.registeredClientRepository.findById(expectedRegisteredClient.getId());
		assertThat(registeredClient).isEqualTo(expectedRegisteredClient);
	}

	// gh-1641
	@Test
	public void saveWhenMultipleWithClientSecretEmptyThenSaved() {
		RegisteredClient registeredClient1 = TestRegisteredClients.registeredClient()
			.id("registration-1")
			.clientId("client-1")
			.clientSecret("")
			.build();
		this.registeredClientRepository.save(registeredClient1);
		RegisteredClient registeredClient2 = TestRegisteredClients.registeredClient()
			.id("registration-2")
			.clientId("client-2")
			.clientSecret("")
			.build();
		this.registeredClientRepository.save(registeredClient2);
	}

	@Test
	public void saveWhenExistingClientIdThenThrowIllegalArgumentException() {
		RegisteredClient registeredClient1 = TestRegisteredClients.registeredClient()
			.id("registration-1")
			.clientId("client-1")
			.build();
		this.registeredClientRepository.save(registeredClient1);
		RegisteredClient registeredClient2 = TestRegisteredClients.registeredClient()
			.id("registration-2")
			.clientId("client-1")
			.build();
		assertThatIllegalArgumentException().isThrownBy(() -> this.registeredClientRepository.save(registeredClient2))
			.withMessage("Registered client must be unique. Found duplicate client identifier: "
					+ registeredClient2.getClientId());
	}

	@Test
	public void saveWhenExistingClientSecretThenThrowIllegalArgumentException() {
		RegisteredClient registeredClient1 = TestRegisteredClients.registeredClient()
			.id("registration-1")
			.clientId("client-1")
			.clientSecret("secret")
			.build();
		this.registeredClientRepository.save(registeredClient1);
		RegisteredClient registeredClient2 = TestRegisteredClients.registeredClient()
			.id("registration-2")
			.clientId("client-2")
			.clientSecret("secret")
			.build();
		assertThatIllegalArgumentException().isThrownBy(() -> this.registeredClientRepository.save(registeredClient2))
			.withMessage("Registered client must be unique. Found duplicate client secret for identifier: "
					+ registeredClient2.getId());
	}

	@Test
	public void saveLoadRegisteredClientWhenCustomStrategiesSetThenCalled() throws Exception {
		RowMapper<RegisteredClient> registeredClientRowMapper = spy(new RegisteredClientRowMapper());
		this.registeredClientRepository.setRegisteredClientRowMapper(registeredClientRowMapper);
		RegisteredClientParametersMapper clientParametersMapper = new RegisteredClientParametersMapper();
		Function<RegisteredClient, List<SqlParameterValue>> registeredClientParametersMapper = spy(
				clientParametersMapper);
		this.registeredClientRepository.setRegisteredClientParametersMapper(registeredClientParametersMapper);

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		this.registeredClientRepository.save(registeredClient);
		RegisteredClient result = this.registeredClientRepository.findById(registeredClient.getId());
		assertThat(result).isEqualTo(registeredClient);
		verify(registeredClientRowMapper).mapRow(any(), anyInt());
		verify(registeredClientParametersMapper).apply(any());
	}

	@Test
	public void findByIdWhenIdNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.registeredClientRepository.findById(null))
				.withMessage("id cannot be empty");
		// @formatter:on
	}

	@Test
	public void findByIdWhenExistsThenFound() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		this.registeredClientRepository.save(registeredClient);
		RegisteredClient result = this.registeredClientRepository.findById(registeredClient.getId());
		assertThat(result).isEqualTo(registeredClient);
	}

	@Test
	public void findByIdWhenNotExistsThenNotFound() {
		RegisteredClient result = this.registeredClientRepository.findById("not-exists");
		assertThat(result).isNull();
	}

	@Test
	public void findByClientIdWhenClientIdNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.registeredClientRepository.findByClientId(null))
				.withMessage("clientId cannot be empty");
		// @formatter:on
	}

	@Test
	public void findByClientIdWhenExistsThenFound() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		this.registeredClientRepository.save(registeredClient);
		RegisteredClient result = this.registeredClientRepository.findByClientId(registeredClient.getClientId());
		assertThat(result).isEqualTo(registeredClient);
	}

	@Test
	public void findByClientIdWhenNotExistsThenNotFound() {
		RegisteredClient result = this.registeredClientRepository.findByClientId("not-exists");
		assertThat(result).isNull();
	}

	@Test
	public void tableDefinitionWhenCustomThenAbleToOverride() {
		EmbeddedDatabase db = createDb(OAUTH2_CUSTOM_REGISTERED_CLIENT_SCHEMA_SQL_RESOURCE);
		CustomJdbcRegisteredClientRepository registeredClientRepository = new CustomJdbcRegisteredClientRepository(
				new JdbcTemplate(db));
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		registeredClientRepository.save(registeredClient);
		RegisteredClient foundRegisteredClient1 = registeredClientRepository.findById(registeredClient.getId());
		assertThat(foundRegisteredClient1).isEqualTo(registeredClient);
		RegisteredClient foundRegisteredClient2 = registeredClientRepository
			.findByClientId(registeredClient.getClientId());
		assertThat(foundRegisteredClient2).isEqualTo(registeredClient);
		db.shutdown();
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

	private static final class CustomJdbcRegisteredClientRepository extends JdbcRegisteredClientRepository {

		// @formatter:off
		private static final String COLUMN_NAMES = "id, "
				+ "clientId, "
				+ "clientIdIssuedAt, "
				+ "clientSecret, "
				+ "clientSecretExpiresAt, "
				+ "clientName, "
				+ "clientAuthenticationMethods, "
				+ "authorizationGrantTypes, "
				+ "redirectUris, "
				+ "postLogoutRedirectUris, "
				+ "scopes, "
				+ "clientSettings,"
				+ "tokenSettings";
		// @formatter:on

		private static final String TABLE_NAME = "oauth2RegisteredClient";

		private static final String LOAD_REGISTERED_CLIENT_SQL = "SELECT " + COLUMN_NAMES + " FROM " + TABLE_NAME
				+ " WHERE ";

		// @formatter:off
		private static final String INSERT_REGISTERED_CLIENT_SQL = "INSERT INTO " + TABLE_NAME
				+ " (" + COLUMN_NAMES + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
		// @formatter:on

		private CustomJdbcRegisteredClientRepository(JdbcOperations jdbcOperations) {
			super(jdbcOperations);
			setRegisteredClientRowMapper(new CustomRegisteredClientRowMapper());
		}

		@Override
		public void save(RegisteredClient registeredClient) {
			List<SqlParameterValue> parameters = getRegisteredClientParametersMapper().apply(registeredClient);
			PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());
			getJdbcOperations().update(INSERT_REGISTERED_CLIENT_SQL, pss);
		}

		@Override
		public RegisteredClient findById(String id) {
			return findBy("id = ?", id);
		}

		@Override
		public RegisteredClient findByClientId(String clientId) {
			return findBy("clientId = ?", clientId);
		}

		private RegisteredClient findBy(String filter, Object... args) {
			List<RegisteredClient> result = getJdbcOperations().query(LOAD_REGISTERED_CLIENT_SQL + filter,
					getRegisteredClientRowMapper(), args);
			return !result.isEmpty() ? result.get(0) : null;
		}

		private static final class CustomRegisteredClientRowMapper implements RowMapper<RegisteredClient> {

			private final ObjectMapper objectMapper = new ObjectMapper();

			private CustomRegisteredClientRowMapper() {
				ClassLoader classLoader = CustomJdbcRegisteredClientRepository.class.getClassLoader();
				List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
				this.objectMapper.registerModules(securityModules);
				this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
			}

			@Override
			public RegisteredClient mapRow(ResultSet rs, int rowNum) throws SQLException {
				Timestamp clientIdIssuedAt = rs.getTimestamp("clientIdIssuedAt");
				Timestamp clientSecretExpiresAt = rs.getTimestamp("clientSecretExpiresAt");
				Set<String> clientAuthenticationMethods = StringUtils
					.commaDelimitedListToSet(rs.getString("clientAuthenticationMethods"));
				Set<String> authorizationGrantTypes = StringUtils
					.commaDelimitedListToSet(rs.getString("authorizationGrantTypes"));
				Set<String> redirectUris = StringUtils.commaDelimitedListToSet(rs.getString("redirectUris"));
				Set<String> postLogoutRedirectUris = StringUtils
					.commaDelimitedListToSet(rs.getString("postLogoutRedirectUris"));
				Set<String> clientScopes = StringUtils.commaDelimitedListToSet(rs.getString("scopes"));

				// @formatter:off
				RegisteredClient.Builder builder = RegisteredClient.withId(rs.getString("id"))
						.clientId(rs.getString("clientId"))
						.clientIdIssuedAt((clientIdIssuedAt != null) ? clientIdIssuedAt.toInstant() : null)
						.clientSecret(rs.getString("clientSecret"))
						.clientSecretExpiresAt((clientSecretExpiresAt != null) ? clientSecretExpiresAt.toInstant() : null)
						.clientName(rs.getString("clientName"))
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

				Map<String, Object> clientSettingsMap = parseMap(rs.getString("clientSettings"));
				builder.clientSettings(ClientSettings.withSettings(clientSettingsMap).build());

				Map<String, Object> tokenSettingsMap = parseMap(rs.getString("tokenSettings"));
				builder.tokenSettings(TokenSettings.withSettings(tokenSettingsMap).build());

				return builder.build();
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

			private static ClientAuthenticationMethod resolveClientAuthenticationMethod(
					String clientAuthenticationMethod) {
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

	}

}
