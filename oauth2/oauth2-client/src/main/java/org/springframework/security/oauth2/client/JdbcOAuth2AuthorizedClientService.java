/*
 * Copyright 2002-2020 the original author or authors.
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
package org.springframework.security.oauth2.client;

import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.jdbc.core.ArgumentPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.SqlParameterValue;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

/**
 * A JDBC implementation of an {@link OAuth2AuthorizedClientService}
 * that uses a {@link JdbcOperations} for {@link OAuth2AuthorizedClient} persistence.
 *
 * <p>
 * <b>NOTE:</b> This {@code OAuth2AuthorizedClientService} depends on the table definition
 * described in "classpath:org/springframework/security/oauth2/client/oauth2-client-schema.sql"
 * and therefore MUST be defined in the database schema.
 *
 * @author Joe Grandja
 * @since 5.3
 * @see OAuth2AuthorizedClientService
 * @see OAuth2AuthorizedClient
 * @see JdbcOperations
 * @see RowMapper
 */
public class JdbcOAuth2AuthorizedClientService implements OAuth2AuthorizedClientService {
	private static final String COLUMN_NAMES =
			"client_registration_id, " +
			"principal_name, " +
			"access_token_type, " +
			"access_token_value, " +
			"access_token_issued_at, " +
			"access_token_expires_at, " +
			"access_token_scopes, " +
			"refresh_token_value, " +
			"refresh_token_issued_at";
	private static final String TABLE_NAME = "oauth2_authorized_client";
	private static final String PK_FILTER = "client_registration_id = ? AND principal_name = ?";
	private static final String LOAD_AUTHORIZED_CLIENT_SQL = "SELECT " + COLUMN_NAMES +
			" FROM " + TABLE_NAME + " WHERE " + PK_FILTER;
	private static final String SAVE_AUTHORIZED_CLIENT_SQL = "INSERT INTO " + TABLE_NAME +
			" (" + COLUMN_NAMES + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
	private static final String REMOVE_AUTHORIZED_CLIENT_SQL = "DELETE FROM " + TABLE_NAME +
			" WHERE " + PK_FILTER;
	protected final JdbcOperations jdbcOperations;
	protected RowMapper<OAuth2AuthorizedClient> authorizedClientRowMapper;
	protected Function<OAuth2AuthorizedClientHolder, List<SqlParameterValue>> authorizedClientParametersMapper;

	/**
	 * Constructs a {@code JdbcOAuth2AuthorizedClientService} using the provided parameters.
	 *
	 * @param jdbcOperations the JDBC operations
	 * @param clientRegistrationRepository the repository of client registrations
	 */
	public JdbcOAuth2AuthorizedClientService(
			JdbcOperations jdbcOperations, ClientRegistrationRepository clientRegistrationRepository) {

		Assert.notNull(jdbcOperations, "jdbcOperations cannot be null");
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.jdbcOperations = jdbcOperations;
		this.authorizedClientRowMapper = new OAuth2AuthorizedClientRowMapper(clientRegistrationRepository);
		this.authorizedClientParametersMapper = new OAuth2AuthorizedClientParametersMapper();
	}

	@Override
	@SuppressWarnings("unchecked")
	public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, String principalName) {
		Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
		Assert.hasText(principalName, "principalName cannot be empty");

		SqlParameterValue[] parameters = new SqlParameterValue[] {
				new SqlParameterValue(Types.VARCHAR, clientRegistrationId),
				new SqlParameterValue(Types.VARCHAR, principalName)
		};
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters);

		List<OAuth2AuthorizedClient> result = this.jdbcOperations.query(
				LOAD_AUTHORIZED_CLIENT_SQL, pss, this.authorizedClientRowMapper);

		return !result.isEmpty() ? (T) result.get(0) : null;
	}

	@Override
	public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
		Assert.notNull(authorizedClient, "authorizedClient cannot be null");
		Assert.notNull(principal, "principal cannot be null");

		List<SqlParameterValue> parameters = this.authorizedClientParametersMapper.apply(
				new OAuth2AuthorizedClientHolder(authorizedClient, principal));
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());

		this.jdbcOperations.update(SAVE_AUTHORIZED_CLIENT_SQL, pss);
	}

	@Override
	public void removeAuthorizedClient(String clientRegistrationId, String principalName) {
		Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
		Assert.hasText(principalName, "principalName cannot be empty");

		SqlParameterValue[] parameters = new SqlParameterValue[] {
				new SqlParameterValue(Types.VARCHAR, clientRegistrationId),
				new SqlParameterValue(Types.VARCHAR, principalName)
		};
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters);

		this.jdbcOperations.update(REMOVE_AUTHORIZED_CLIENT_SQL, pss);
	}

	/**
	 * Sets the {@link RowMapper} used for mapping the current row in {@code java.sql.ResultSet} to {@link OAuth2AuthorizedClient}.
	 * The default is {@link OAuth2AuthorizedClientRowMapper}.
	 *
	 * @param authorizedClientRowMapper the {@link RowMapper} used for mapping the current row in {@code java.sql.ResultSet} to {@link OAuth2AuthorizedClient}
	 */
	public final void setAuthorizedClientRowMapper(RowMapper<OAuth2AuthorizedClient> authorizedClientRowMapper) {
		Assert.notNull(authorizedClientRowMapper, "authorizedClientRowMapper cannot be null");
		this.authorizedClientRowMapper = authorizedClientRowMapper;
	}

	/**
	 * Sets the {@code Function} used for mapping {@link OAuth2AuthorizedClientHolder} to a {@code List} of {@link SqlParameterValue}.
	 * The default is {@link OAuth2AuthorizedClientParametersMapper}.
	 *
	 * @param authorizedClientParametersMapper the {@code Function} used for mapping {@link OAuth2AuthorizedClientHolder} to a {@code List} of {@link SqlParameterValue}
	 */
	public final void setAuthorizedClientParametersMapper(Function<OAuth2AuthorizedClientHolder, List<SqlParameterValue>> authorizedClientParametersMapper) {
		Assert.notNull(authorizedClientParametersMapper, "authorizedClientParametersMapper cannot be null");
		this.authorizedClientParametersMapper = authorizedClientParametersMapper;
	}

	/**
	 * The default {@link RowMapper} that maps the current row
	 * in {@code java.sql.ResultSet} to {@link OAuth2AuthorizedClient}.
	 */
	public static class OAuth2AuthorizedClientRowMapper implements RowMapper<OAuth2AuthorizedClient> {
		protected final ClientRegistrationRepository clientRegistrationRepository;

		public OAuth2AuthorizedClientRowMapper(ClientRegistrationRepository clientRegistrationRepository) {
			Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
			this.clientRegistrationRepository = clientRegistrationRepository;
		}

		@Override
		public OAuth2AuthorizedClient mapRow(ResultSet rs, int rowNum) throws SQLException {
			String clientRegistrationId = rs.getString("client_registration_id");
			ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(
					clientRegistrationId);
			if (clientRegistration == null) {
				throw new DataRetrievalFailureException("The ClientRegistration with id '" +
						clientRegistrationId + "' exists in the data source, " +
						"however, it was not found in the ClientRegistrationRepository.");
			}

			OAuth2AccessToken.TokenType tokenType = null;
			if (OAuth2AccessToken.TokenType.BEARER.getValue().equalsIgnoreCase(
					rs.getString("access_token_type"))) {
				tokenType = OAuth2AccessToken.TokenType.BEARER;
			}
			String tokenValue = new String(rs.getBytes("access_token_value"), StandardCharsets.UTF_8);
			Instant issuedAt = rs.getTimestamp("access_token_issued_at").toInstant();
			Instant expiresAt = rs.getTimestamp("access_token_expires_at").toInstant();
			Set<String> scopes = Collections.emptySet();
			String accessTokenScopes = rs.getString("access_token_scopes");
			if (accessTokenScopes != null) {
				scopes = StringUtils.commaDelimitedListToSet(accessTokenScopes);
			}
			OAuth2AccessToken accessToken = new OAuth2AccessToken(
					tokenType, tokenValue, issuedAt, expiresAt, scopes);

			OAuth2RefreshToken refreshToken = null;
			byte[] refreshTokenValue = rs.getBytes("refresh_token_value");
			if (refreshTokenValue != null) {
				tokenValue = new String(refreshTokenValue, StandardCharsets.UTF_8);
				issuedAt = null;
				Timestamp refreshTokenIssuedAt = rs.getTimestamp("refresh_token_issued_at");
				if (refreshTokenIssuedAt != null) {
					issuedAt = refreshTokenIssuedAt.toInstant();
				}
				refreshToken = new OAuth2RefreshToken(tokenValue, issuedAt);
			}

			String principalName = rs.getString("principal_name");

			return new OAuth2AuthorizedClient(
					clientRegistration, principalName, accessToken, refreshToken);
		}
	}

	/**
	 * The default {@code Function} that maps {@link OAuth2AuthorizedClientHolder}
	 * to a {@code List} of {@link SqlParameterValue}.
	 */
	public static class OAuth2AuthorizedClientParametersMapper implements Function<OAuth2AuthorizedClientHolder, List<SqlParameterValue>> {

		@Override
		public List<SqlParameterValue> apply(OAuth2AuthorizedClientHolder authorizedClientHolder) {
			OAuth2AuthorizedClient authorizedClient = authorizedClientHolder.getAuthorizedClient();
			Authentication principal = authorizedClientHolder.getPrincipal();
			ClientRegistration clientRegistration = authorizedClient.getClientRegistration();
			OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
			OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();

			List<SqlParameterValue> parameters = new ArrayList<>();
			parameters.add(new SqlParameterValue(
					Types.VARCHAR, clientRegistration.getRegistrationId()));
			parameters.add(new SqlParameterValue(
					Types.VARCHAR, principal.getName()));
			parameters.add(new SqlParameterValue(
					Types.VARCHAR, accessToken.getTokenType().getValue()));
			parameters.add(new SqlParameterValue(
					Types.BLOB, accessToken.getTokenValue().getBytes(StandardCharsets.UTF_8)));
			parameters.add(new SqlParameterValue(
					Types.TIMESTAMP, Timestamp.from(accessToken.getIssuedAt())));
			parameters.add(new SqlParameterValue(
					Types.TIMESTAMP, Timestamp.from(accessToken.getExpiresAt())));
			String accessTokenScopes = null;
			if (!CollectionUtils.isEmpty(accessToken.getScopes())) {
				accessTokenScopes = StringUtils.collectionToDelimitedString(accessToken.getScopes(), ",");
			}
			parameters.add(new SqlParameterValue(
					Types.VARCHAR, accessTokenScopes));
			byte[] refreshTokenValue = null;
			Timestamp refreshTokenIssuedAt = null;
			if (refreshToken != null) {
				refreshTokenValue = refreshToken.getTokenValue().getBytes(StandardCharsets.UTF_8);
				if (refreshToken.getIssuedAt() != null) {
					refreshTokenIssuedAt = Timestamp.from(refreshToken.getIssuedAt());
				}
			}
			parameters.add(new SqlParameterValue(
					Types.BLOB, refreshTokenValue));
			parameters.add(new SqlParameterValue(
					Types.TIMESTAMP, refreshTokenIssuedAt));

			return parameters;
		}
	}

	/**
	 * A holder for an {@link OAuth2AuthorizedClient} and End-User {@link Authentication} (Resource Owner).
	 */
	public static final class OAuth2AuthorizedClientHolder {
		private final OAuth2AuthorizedClient authorizedClient;
		private final Authentication principal;

		/**
		 * Constructs an {@code OAuth2AuthorizedClientHolder} using the provided parameters.
		 *
		 * @param authorizedClient the authorized client
		 * @param principal the End-User {@link Authentication} (Resource Owner)
		 */
		public OAuth2AuthorizedClientHolder(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
			Assert.notNull(authorizedClient, "authorizedClient cannot be null");
			Assert.notNull(principal, "principal cannot be null");
			this.authorizedClient = authorizedClient;
			this.principal = principal;
		}

		/**
		 * Returns the {@link OAuth2AuthorizedClient}.
		 *
		 * @return the {@link OAuth2AuthorizedClient}
		 */
		public OAuth2AuthorizedClient getAuthorizedClient() {
			return this.authorizedClient;
		}

		/**
		 * Returns the End-User {@link Authentication} (Resource Owner).
		 *
		 * @return the End-User {@link Authentication} (Resource Owner)
		 */
		public Authentication getPrincipal() {
			return this.principal;
		}
	}
}
