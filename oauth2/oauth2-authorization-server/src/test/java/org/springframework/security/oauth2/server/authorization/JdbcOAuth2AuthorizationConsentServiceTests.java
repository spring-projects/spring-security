/*
 * Copyright 2020-2022 the original author or authors.
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

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.jdbc.core.ArgumentPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.SqlParameterValue;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.util.StringUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link JdbcOAuth2AuthorizationConsentService}.
 *
 * @author Ovidiu Popa
 */
public class JdbcOAuth2AuthorizationConsentServiceTests {

	private static final String OAUTH2_AUTHORIZATION_CONSENT_SCHEMA_SQL_RESOURCE = "org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql";

	private static final String CUSTOM_OAUTH2_AUTHORIZATION_CONSENT_SCHEMA_SQL_RESOURCE = "org/springframework/security/oauth2/server/authorization/custom-oauth2-authorization-consent-schema.sql";

	private static final String PRINCIPAL_NAME = "principal-name";

	private static final RegisteredClient REGISTERED_CLIENT = TestRegisteredClients.registeredClient().build();

	private static final OAuth2AuthorizationConsent AUTHORIZATION_CONSENT = OAuth2AuthorizationConsent
		.withId(REGISTERED_CLIENT.getId(), PRINCIPAL_NAME)
		.authority(new SimpleGrantedAuthority("SCOPE_scope1"))
		.authority(new SimpleGrantedAuthority("SCOPE_scope2"))
		.authority(new SimpleGrantedAuthority("SCOPE_scope3"))
		.authority(new SimpleGrantedAuthority("authority-a"))
		.authority(new SimpleGrantedAuthority("authority-b"))
		.build();

	private EmbeddedDatabase db;

	private JdbcOperations jdbcOperations;

	private RegisteredClientRepository registeredClientRepository;

	private JdbcOAuth2AuthorizationConsentService authorizationConsentService;

	@BeforeEach
	public void setUp() {
		this.db = createDb();
		this.jdbcOperations = new JdbcTemplate(this.db);
		this.registeredClientRepository = mock(RegisteredClientRepository.class);
		this.authorizationConsentService = new JdbcOAuth2AuthorizationConsentService(this.jdbcOperations,
				this.registeredClientRepository);
	}

	@AfterEach
	public void tearDown() {
		this.db.shutdown();
	}

	@Test
	public void constructorWhenJdbcOperationsIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatThrownBy(() -> new JdbcOAuth2AuthorizationConsentService(null, this.registeredClientRepository))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("jdbcOperations cannot be null");
		// @formatter:on
	}

	@Test
	public void constructorWhenRegisteredClientRepositoryIsNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatThrownBy(() -> new JdbcOAuth2AuthorizationConsentService(this.jdbcOperations, null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("registeredClientRepository cannot be null");
		// @formatter:on
	}

	@Test
	public void setAuthorizationConsentRowMapperWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatThrownBy(() -> this.authorizationConsentService.setAuthorizationConsentRowMapper(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationConsentRowMapper cannot be null");
		// @formatter:on
	}

	@Test
	public void setAuthorizationConsentParametersMapperWhenNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatThrownBy(() -> this.authorizationConsentService.setAuthorizationConsentParametersMapper(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorizationConsentParametersMapper cannot be null");
		// @formatter:on
	}

	@Test
	public void saveWhenAuthorizationConsentNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.authorizationConsentService.save(null))
				.withMessage("authorizationConsent cannot be null");
		// @formatter:on
	}

	@Test
	public void saveWhenAuthorizationConsentNewThenSaved() {
		OAuth2AuthorizationConsent expectedAuthorizationConsent = OAuth2AuthorizationConsent
			.withId("new-client", "new-principal")
			.authority(new SimpleGrantedAuthority("new.authority"))
			.build();

		RegisteredClient newRegisteredClient = TestRegisteredClients.registeredClient().id("new-client").build();

		given(this.registeredClientRepository.findById(eq(newRegisteredClient.getId())))
			.willReturn(newRegisteredClient);

		this.authorizationConsentService.save(expectedAuthorizationConsent);

		OAuth2AuthorizationConsent authorizationConsent = this.authorizationConsentService.findById("new-client",
				"new-principal");
		assertThat(authorizationConsent).isEqualTo(expectedAuthorizationConsent);
	}

	@Test
	public void saveWhenAuthorizationConsentExistsThenUpdated() {
		OAuth2AuthorizationConsent expectedAuthorizationConsent = OAuth2AuthorizationConsent.from(AUTHORIZATION_CONSENT)
			.authority(new SimpleGrantedAuthority("new.authority"))
			.build();
		given(this.registeredClientRepository.findById(eq(REGISTERED_CLIENT.getId()))).willReturn(REGISTERED_CLIENT);

		this.authorizationConsentService.save(expectedAuthorizationConsent);

		OAuth2AuthorizationConsent authorizationConsent = this.authorizationConsentService
			.findById(AUTHORIZATION_CONSENT.getRegisteredClientId(), AUTHORIZATION_CONSENT.getPrincipalName());
		assertThat(authorizationConsent).isEqualTo(expectedAuthorizationConsent);
		assertThat(authorizationConsent).isNotEqualTo(AUTHORIZATION_CONSENT);
	}

	@Test
	public void saveLoadAuthorizationConsentWhenCustomStrategiesSetThenCalled() throws Exception {
		given(this.registeredClientRepository.findById(eq(REGISTERED_CLIENT.getId()))).willReturn(REGISTERED_CLIENT);

		JdbcOAuth2AuthorizationConsentService.OAuth2AuthorizationConsentRowMapper authorizationConsentRowMapper = spy(
				new JdbcOAuth2AuthorizationConsentService.OAuth2AuthorizationConsentRowMapper(
						this.registeredClientRepository));
		this.authorizationConsentService.setAuthorizationConsentRowMapper(authorizationConsentRowMapper);
		JdbcOAuth2AuthorizationConsentService.OAuth2AuthorizationConsentParametersMapper authorizationConsentParametersMapper = spy(
				new JdbcOAuth2AuthorizationConsentService.OAuth2AuthorizationConsentParametersMapper());
		this.authorizationConsentService.setAuthorizationConsentParametersMapper(authorizationConsentParametersMapper);

		this.authorizationConsentService.save(AUTHORIZATION_CONSENT);
		OAuth2AuthorizationConsent authorizationConsent = this.authorizationConsentService
			.findById(AUTHORIZATION_CONSENT.getRegisteredClientId(), AUTHORIZATION_CONSENT.getPrincipalName());
		assertThat(authorizationConsent).isEqualTo(AUTHORIZATION_CONSENT);
		verify(authorizationConsentRowMapper).mapRow(any(), anyInt());
		verify(authorizationConsentParametersMapper).apply(any());
	}

	@Test
	public void removeWhenAuthorizationConsentNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.authorizationConsentService.remove(null))
			.withMessage("authorizationConsent cannot be null");
	}

	@Test
	public void removeWhenAuthorizationConsentProvidedThenRemoved() {
		this.authorizationConsentService.remove(AUTHORIZATION_CONSENT);
		assertThat(this.authorizationConsentService.findById(AUTHORIZATION_CONSENT.getRegisteredClientId(),
				AUTHORIZATION_CONSENT.getPrincipalName()))
			.isNull();
	}

	@Test
	public void findByIdWhenRegisteredClientIdNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.authorizationConsentService.findById(null, "some-user"))
			.withMessage("registeredClientId cannot be empty");
	}

	@Test
	public void findByIdWhenPrincipalNameNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.authorizationConsentService.findById("some-client", null))
			.withMessage("principalName cannot be empty");
	}

	@Test
	public void findByIdWhenAuthorizationConsentExistsThenFound() {
		given(this.registeredClientRepository.findById(eq(REGISTERED_CLIENT.getId()))).willReturn(REGISTERED_CLIENT);

		this.authorizationConsentService.save(AUTHORIZATION_CONSENT);
		OAuth2AuthorizationConsent authorizationConsent = this.authorizationConsentService
			.findById(AUTHORIZATION_CONSENT.getRegisteredClientId(), AUTHORIZATION_CONSENT.getPrincipalName());
		assertThat(authorizationConsent).isNotNull();
	}

	@Test
	public void findByIdWhenAuthorizationConsentDoesNotExistThenNull() {
		this.authorizationConsentService.save(AUTHORIZATION_CONSENT);
		assertThat(this.authorizationConsentService.findById("unknown-client", PRINCIPAL_NAME)).isNull();
		assertThat(this.authorizationConsentService.findById(REGISTERED_CLIENT.getId(), "unknown-user")).isNull();
	}

	@Test
	public void tableDefinitionWhenCustomThenAbleToOverride() {
		given(this.registeredClientRepository.findById(eq(REGISTERED_CLIENT.getId()))).willReturn(REGISTERED_CLIENT);

		EmbeddedDatabase db = createDb(CUSTOM_OAUTH2_AUTHORIZATION_CONSENT_SCHEMA_SQL_RESOURCE);
		OAuth2AuthorizationConsentService authorizationConsentService = new CustomJdbcOAuth2AuthorizationConsentService(
				new JdbcTemplate(db), this.registeredClientRepository);
		authorizationConsentService.save(AUTHORIZATION_CONSENT);
		OAuth2AuthorizationConsent foundAuthorizationConsent1 = authorizationConsentService
			.findById(AUTHORIZATION_CONSENT.getRegisteredClientId(), AUTHORIZATION_CONSENT.getPrincipalName());
		assertThat(foundAuthorizationConsent1).isEqualTo(AUTHORIZATION_CONSENT);
		authorizationConsentService.remove(AUTHORIZATION_CONSENT);
		OAuth2AuthorizationConsent foundAuthorizationConsent2 = authorizationConsentService
			.findById(AUTHORIZATION_CONSENT.getRegisteredClientId(), AUTHORIZATION_CONSENT.getPrincipalName());
		assertThat(foundAuthorizationConsent2).isNull();
		db.shutdown();
	}

	private static EmbeddedDatabase createDb() {
		return createDb(OAUTH2_AUTHORIZATION_CONSENT_SCHEMA_SQL_RESOURCE);
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

	private static final class CustomJdbcOAuth2AuthorizationConsentService
			extends JdbcOAuth2AuthorizationConsentService {

		// @formatter:off
		private static final String COLUMN_NAMES = "registeredClientId, "
				+ "principalName, "
				+ "authorities";
		// @formatter:on

		private static final String TABLE_NAME = "oauth2AuthorizationConsent";

		private static final String PK_FILTER = "registeredClientId = ? AND principalName = ?";

		// @formatter:off
		private static final String LOAD_AUTHORIZATION_CONSENT_SQL = "SELECT " + COLUMN_NAMES
				+ " FROM " + TABLE_NAME
				+ " WHERE " + PK_FILTER;
		// @formatter:on

		// @formatter:off
		private static final String SAVE_AUTHORIZATION_CONSENT_SQL = "INSERT INTO " + TABLE_NAME
				+ " (" + COLUMN_NAMES + ") VALUES (?, ?, ?)";
		// @formatter:on

		private static final String REMOVE_AUTHORIZATION_CONSENT_SQL = "DELETE FROM " + TABLE_NAME + " WHERE "
				+ PK_FILTER;

		private CustomJdbcOAuth2AuthorizationConsentService(JdbcOperations jdbcOperations,
				RegisteredClientRepository registeredClientRepository) {
			super(jdbcOperations, registeredClientRepository);
			setAuthorizationConsentRowMapper(new CustomOAuth2AuthorizationConsentRowMapper(registeredClientRepository));
		}

		@Override
		public void save(OAuth2AuthorizationConsent authorizationConsent) {
			List<SqlParameterValue> parameters = getAuthorizationConsentParametersMapper().apply(authorizationConsent);
			PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());
			getJdbcOperations().update(SAVE_AUTHORIZATION_CONSENT_SQL, pss);
		}

		@Override
		public void remove(OAuth2AuthorizationConsent authorizationConsent) {
			SqlParameterValue[] parameters = new SqlParameterValue[] {
					new SqlParameterValue(Types.VARCHAR, authorizationConsent.getRegisteredClientId()),
					new SqlParameterValue(Types.VARCHAR, authorizationConsent.getPrincipalName()) };
			PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters);
			getJdbcOperations().update(REMOVE_AUTHORIZATION_CONSENT_SQL, pss);
		}

		@Override
		public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
			SqlParameterValue[] parameters = new SqlParameterValue[] {
					new SqlParameterValue(Types.VARCHAR, registeredClientId),
					new SqlParameterValue(Types.VARCHAR, principalName) };
			PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters);
			List<OAuth2AuthorizationConsent> result = getJdbcOperations().query(LOAD_AUTHORIZATION_CONSENT_SQL, pss,
					getAuthorizationConsentRowMapper());
			return !result.isEmpty() ? result.get(0) : null;
		}

		private static final class CustomOAuth2AuthorizationConsentRowMapper
				extends JdbcOAuth2AuthorizationConsentService.OAuth2AuthorizationConsentRowMapper {

			private CustomOAuth2AuthorizationConsentRowMapper(RegisteredClientRepository registeredClientRepository) {
				super(registeredClientRepository);
			}

			@Override
			public OAuth2AuthorizationConsent mapRow(ResultSet rs, int rowNum) throws SQLException {
				String registeredClientId = rs.getString("registeredClientId");
				RegisteredClient registeredClient = getRegisteredClientRepository().findById(registeredClientId);
				if (registeredClient == null) {
					throw new DataRetrievalFailureException("The RegisteredClient with id '" + registeredClientId
							+ "' was not found in the RegisteredClientRepository.");
				}

				String principalName = rs.getString("principalName");

				OAuth2AuthorizationConsent.Builder builder = OAuth2AuthorizationConsent.withId(registeredClientId,
						principalName);
				String authorizationConsentAuthorities = rs.getString("authorities");
				if (authorizationConsentAuthorities != null) {
					for (String authority : StringUtils.commaDelimitedListToSet(authorizationConsentAuthorities)) {
						builder.authority(new SimpleGrantedAuthority(authority));
					}
				}
				return builder.build();
			}

		}

	}

}
