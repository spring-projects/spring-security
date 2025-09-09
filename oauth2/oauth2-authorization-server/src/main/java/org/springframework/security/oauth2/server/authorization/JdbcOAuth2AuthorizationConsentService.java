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

package org.springframework.security.oauth2.server.authorization;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.context.annotation.ImportRuntimeHints;
import org.springframework.core.io.ClassPathResource;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.jdbc.core.ArgumentPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.SqlParameterValue;
import org.springframework.lang.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * A JDBC implementation of an {@link OAuth2AuthorizationConsentService} that uses a
 * {@link JdbcOperations} for {@link OAuth2AuthorizationConsent} persistence.
 *
 * <p>
 * <b>IMPORTANT:</b> This {@code OAuth2AuthorizationConsentService} depends on the table
 * definition described in
 * "classpath:org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql"
 * and therefore MUST be defined in the database schema.
 *
 * <p>
 * <b>NOTE:</b> This {@code OAuth2AuthorizationConsentService} is a simplified JDBC
 * implementation that MAY be used in a production environment. However, it does have
 * limitations as it likely won't perform well in an environment requiring high
 * throughput. The expectation is that the consuming application will provide their own
 * implementation of {@code OAuth2AuthorizationConsentService} that meets the performance
 * requirements for its deployment environment.
 *
 * @author Ovidiu Popa
 * @author Josh Long
 * @since 7.0
 * @see OAuth2AuthorizationConsentService
 * @see OAuth2AuthorizationConsent
 * @see JdbcOperations
 * @see RowMapper
 */
@ImportRuntimeHints(JdbcOAuth2AuthorizationConsentService.JdbcOAuth2AuthorizationConsentServiceRuntimeHintsRegistrar.class)
public class JdbcOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

	// @formatter:off
	private static final String COLUMN_NAMES = "registered_client_id, "
			+ "principal_name, "
			+ "authorities";
	// @formatter:on

	private static final String TABLE_NAME = "oauth2_authorization_consent";

	private static final String PK_FILTER = "registered_client_id = ? AND principal_name = ?";

	// @formatter:off
	private static final String LOAD_AUTHORIZATION_CONSENT_SQL = "SELECT " + COLUMN_NAMES
			+ " FROM " + TABLE_NAME
			+ " WHERE " + PK_FILTER;
	// @formatter:on

	// @formatter:off
	private static final String SAVE_AUTHORIZATION_CONSENT_SQL = "INSERT INTO " + TABLE_NAME
			+ " (" + COLUMN_NAMES + ") VALUES (?, ?, ?)";
	// @formatter:on

	// @formatter:off
	private static final String UPDATE_AUTHORIZATION_CONSENT_SQL = "UPDATE " + TABLE_NAME
			+ " SET authorities = ?"
			+ " WHERE " + PK_FILTER;
	// @formatter:on

	private static final String REMOVE_AUTHORIZATION_CONSENT_SQL = "DELETE FROM " + TABLE_NAME + " WHERE " + PK_FILTER;

	private final JdbcOperations jdbcOperations;

	private RowMapper<OAuth2AuthorizationConsent> authorizationConsentRowMapper;

	private Function<OAuth2AuthorizationConsent, List<SqlParameterValue>> authorizationConsentParametersMapper;

	/**
	 * Constructs a {@code JdbcOAuth2AuthorizationConsentService} using the provided
	 * parameters.
	 * @param jdbcOperations the JDBC operations
	 * @param registeredClientRepository the registered client repository
	 */
	public JdbcOAuth2AuthorizationConsentService(JdbcOperations jdbcOperations,
			RegisteredClientRepository registeredClientRepository) {
		Assert.notNull(jdbcOperations, "jdbcOperations cannot be null");
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		this.jdbcOperations = jdbcOperations;
		this.authorizationConsentRowMapper = new OAuth2AuthorizationConsentRowMapper(registeredClientRepository);
		this.authorizationConsentParametersMapper = new OAuth2AuthorizationConsentParametersMapper();
	}

	@Override
	public void save(OAuth2AuthorizationConsent authorizationConsent) {
		Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
		OAuth2AuthorizationConsent existingAuthorizationConsent = findById(authorizationConsent.getRegisteredClientId(),
				authorizationConsent.getPrincipalName());
		if (existingAuthorizationConsent == null) {
			insertAuthorizationConsent(authorizationConsent);
		}
		else {
			updateAuthorizationConsent(authorizationConsent);
		}
	}

	private void updateAuthorizationConsent(OAuth2AuthorizationConsent authorizationConsent) {
		List<SqlParameterValue> parameters = this.authorizationConsentParametersMapper.apply(authorizationConsent);
		SqlParameterValue registeredClientId = parameters.remove(0);
		SqlParameterValue principalName = parameters.remove(0);
		parameters.add(registeredClientId);
		parameters.add(principalName);
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());
		this.jdbcOperations.update(UPDATE_AUTHORIZATION_CONSENT_SQL, pss);
	}

	private void insertAuthorizationConsent(OAuth2AuthorizationConsent authorizationConsent) {
		List<SqlParameterValue> parameters = this.authorizationConsentParametersMapper.apply(authorizationConsent);
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());
		this.jdbcOperations.update(SAVE_AUTHORIZATION_CONSENT_SQL, pss);
	}

	@Override
	public void remove(OAuth2AuthorizationConsent authorizationConsent) {
		Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
		SqlParameterValue[] parameters = new SqlParameterValue[] {
				new SqlParameterValue(Types.VARCHAR, authorizationConsent.getRegisteredClientId()),
				new SqlParameterValue(Types.VARCHAR, authorizationConsent.getPrincipalName()) };
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters);
		this.jdbcOperations.update(REMOVE_AUTHORIZATION_CONSENT_SQL, pss);
	}

	@Override
	@Nullable
	public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
		Assert.hasText(registeredClientId, "registeredClientId cannot be empty");
		Assert.hasText(principalName, "principalName cannot be empty");
		SqlParameterValue[] parameters = new SqlParameterValue[] {
				new SqlParameterValue(Types.VARCHAR, registeredClientId),
				new SqlParameterValue(Types.VARCHAR, principalName) };
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters);
		List<OAuth2AuthorizationConsent> result = this.jdbcOperations.query(LOAD_AUTHORIZATION_CONSENT_SQL, pss,
				this.authorizationConsentRowMapper);
		return !result.isEmpty() ? result.get(0) : null;
	}

	/**
	 * Sets the {@link RowMapper} used for mapping the current row in
	 * {@code java.sql.ResultSet} to {@link OAuth2AuthorizationConsent}. The default is
	 * {@link OAuth2AuthorizationConsentRowMapper}.
	 * @param authorizationConsentRowMapper the {@link RowMapper} used for mapping the
	 * current row in {@code ResultSet} to {@link OAuth2AuthorizationConsent}
	 */
	public final void setAuthorizationConsentRowMapper(
			RowMapper<OAuth2AuthorizationConsent> authorizationConsentRowMapper) {
		Assert.notNull(authorizationConsentRowMapper, "authorizationConsentRowMapper cannot be null");
		this.authorizationConsentRowMapper = authorizationConsentRowMapper;
	}

	/**
	 * Sets the {@code Function} used for mapping {@link OAuth2AuthorizationConsent} to a
	 * {@code List} of {@link SqlParameterValue}. The default is
	 * {@link OAuth2AuthorizationConsentParametersMapper}.
	 * @param authorizationConsentParametersMapper the {@code Function} used for mapping
	 * {@link OAuth2AuthorizationConsent} to a {@code List} of {@link SqlParameterValue}
	 */
	public final void setAuthorizationConsentParametersMapper(
			Function<OAuth2AuthorizationConsent, List<SqlParameterValue>> authorizationConsentParametersMapper) {
		Assert.notNull(authorizationConsentParametersMapper, "authorizationConsentParametersMapper cannot be null");
		this.authorizationConsentParametersMapper = authorizationConsentParametersMapper;
	}

	protected final JdbcOperations getJdbcOperations() {
		return this.jdbcOperations;
	}

	protected final RowMapper<OAuth2AuthorizationConsent> getAuthorizationConsentRowMapper() {
		return this.authorizationConsentRowMapper;
	}

	protected final Function<OAuth2AuthorizationConsent, List<SqlParameterValue>> getAuthorizationConsentParametersMapper() {
		return this.authorizationConsentParametersMapper;
	}

	/**
	 * The default {@link RowMapper} that maps the current row in {@code ResultSet} to
	 * {@link OAuth2AuthorizationConsent}.
	 */
	public static class OAuth2AuthorizationConsentRowMapper implements RowMapper<OAuth2AuthorizationConsent> {

		private final RegisteredClientRepository registeredClientRepository;

		public OAuth2AuthorizationConsentRowMapper(RegisteredClientRepository registeredClientRepository) {
			Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
			this.registeredClientRepository = registeredClientRepository;
		}

		@Override
		public OAuth2AuthorizationConsent mapRow(ResultSet rs, int rowNum) throws SQLException {
			String registeredClientId = rs.getString("registered_client_id");
			RegisteredClient registeredClient = this.registeredClientRepository.findById(registeredClientId);
			if (registeredClient == null) {
				throw new DataRetrievalFailureException("The RegisteredClient with id '" + registeredClientId
						+ "' was not found in the RegisteredClientRepository.");
			}

			String principalName = rs.getString("principal_name");

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

		protected final RegisteredClientRepository getRegisteredClientRepository() {
			return this.registeredClientRepository;
		}

	}

	/**
	 * The default {@code Function} that maps {@link OAuth2AuthorizationConsent} to a
	 * {@code List} of {@link SqlParameterValue}.
	 */
	public static class OAuth2AuthorizationConsentParametersMapper
			implements Function<OAuth2AuthorizationConsent, List<SqlParameterValue>> {

		@Override
		public List<SqlParameterValue> apply(OAuth2AuthorizationConsent authorizationConsent) {
			List<SqlParameterValue> parameters = new ArrayList<>();
			parameters.add(new SqlParameterValue(Types.VARCHAR, authorizationConsent.getRegisteredClientId()));
			parameters.add(new SqlParameterValue(Types.VARCHAR, authorizationConsent.getPrincipalName()));

			Set<String> authorities = new HashSet<>();
			for (GrantedAuthority authority : authorizationConsent.getAuthorities()) {
				authorities.add(authority.getAuthority());
			}
			parameters
				.add(new SqlParameterValue(Types.VARCHAR, StringUtils.collectionToDelimitedString(authorities, ",")));
			return parameters;
		}

	}

	static class JdbcOAuth2AuthorizationConsentServiceRuntimeHintsRegistrar implements RuntimeHintsRegistrar {

		@Override
		public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
			hints.resources()
				.registerResource(new ClassPathResource(
						"org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql"));
		}

	}

}
