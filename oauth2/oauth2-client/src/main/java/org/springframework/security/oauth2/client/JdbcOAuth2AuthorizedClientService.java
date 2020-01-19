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

import org.springframework.context.annotation.Configuration;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.jdbc.core.ArgumentTypePreparedStatementSetter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import javax.sql.DataSource;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * A JDBC implementation of an {@link OAuth2AuthorizedClientService}
 * that uses a {@link JdbcTemplate} for {@link OAuth2AuthorizedClient} persistence.
 *
 * <p>
 * In order to enable {@link Transactional} for this {@code OAuth2AuthorizedClientService},
 * ensure you declare {@link EnableTransactionManagement} within a {@link Configuration}.
 *
 * <p>
 * <b>NOTE:</b> This {@code OAuth2AuthorizedClientService} depends on the following
 * table definition and therefore MUST be defined in the database schema.
 *
 * <pre>
 * CREATE TABLE oauth2_authorized_client (
 *   client_registration_id varchar(100) NOT NULL,
 *   principal_name varchar(100) NOT NULL,
 *   access_token_type varchar(75) NOT NULL,
 *   access_token_value varchar(7000) NOT NULL,
 *   access_token_issued_at timestamp NOT NULL,
 *   access_token_expires_at timestamp NOT NULL,
 *   access_token_scopes varchar(1000) DEFAULT NULL,
 *   refresh_token_value varchar(7000) DEFAULT NULL,
 *   refresh_token_issued_at timestamp DEFAULT NULL,
 *   created_at timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
 *   PRIMARY KEY (client_registration_id, principal_name)
 * );
 * </pre>
 *
 * @author Joe Grandja
 * @since 5.3
 * @see OAuth2AuthorizedClientService
 * @see OAuth2AuthorizedClient
 * @see JdbcTemplate
 */
@Repository
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
	protected final JdbcTemplate jdbcTemplate;
	protected final ClientRegistrationRepository clientRegistrationRepository;

	/**
	 * Constructs a {@code JdbcOAuth2AuthorizedClientService} using the provided parameters.
	 *
	 * @param dataSource the data source
	 * @param clientRegistrationRepository the repository of client registrations
	 */
	public JdbcOAuth2AuthorizedClientService(
			DataSource dataSource, ClientRegistrationRepository clientRegistrationRepository) {

		Assert.notNull(dataSource, "dataSource cannot be null");
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.jdbcTemplate = new JdbcTemplate(dataSource);
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	@Transactional(readOnly = true)
	@Override
	@SuppressWarnings("unchecked")
	public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, String principalName) {
		Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
		Assert.hasText(principalName, "principalName cannot be empty");

		Object[] args = {clientRegistrationId, principalName};
		int[] argTypes = {Types.VARCHAR, Types.VARCHAR};
		PreparedStatementSetter pss = new ArgumentTypePreparedStatementSetter(args, argTypes);

		List<OAuth2AuthorizedClient> result = this.jdbcTemplate.query(
				LOAD_AUTHORIZED_CLIENT_SQL,
				pss,
				(rs, rowNum) -> {
					OAuth2AuthorizedClientData authorizedClientData = mapData(rs);

					ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(
							authorizedClientData.clientRegistrationId);
					if (clientRegistration == null) {
						throw new DataRetrievalFailureException("The ClientRegistration with id '" +
								authorizedClientData.clientRegistrationId + "' exists in the data source, " +
								"however, it was not found in the ClientRegistrationRepository.");
					}

					OAuth2AccessToken.TokenType tokenType = null;
					if (OAuth2AccessToken.TokenType.BEARER.getValue().equalsIgnoreCase(authorizedClientData.accessTokenType)) {
						tokenType = OAuth2AccessToken.TokenType.BEARER;
					}
					String tokenValue = authorizedClientData.accessTokenValue;		// TODO Decrypt
					Instant issuedAt = authorizedClientData.accessTokenIssuedAt.toInstant();
					Instant expiresAt = authorizedClientData.accessTokenExpiresAt.toInstant();
					Set<String> scopes = Collections.emptySet();
					if (authorizedClientData.accessTokenScopes != null) {
						scopes = StringUtils.commaDelimitedListToSet(authorizedClientData.accessTokenScopes);
					}
					OAuth2AccessToken accessToken = new OAuth2AccessToken(
							tokenType, tokenValue, issuedAt, expiresAt, scopes);

					OAuth2RefreshToken refreshToken = null;
					if (authorizedClientData.refreshTokenValue != null) {
						tokenValue = authorizedClientData.refreshTokenValue;	// TODO Decrypt
						issuedAt = null;
						if (authorizedClientData.refreshTokenIssuedAt != null) {
							issuedAt = authorizedClientData.refreshTokenIssuedAt.toInstant();
						}
						refreshToken = new OAuth2RefreshToken(tokenValue, issuedAt);
					}

					return new OAuth2AuthorizedClient(clientRegistration,
							authorizedClientData.principalName, accessToken, refreshToken);
				});

		return !result.isEmpty() ? (T) result.get(0) : null;
	}

	@Transactional
	@Override
	public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
		Assert.notNull(authorizedClient, "authorizedClient cannot be null");
		Assert.notNull(principal, "principal cannot be null");

		OAuth2AuthorizedClientData authorizedClientData = mapData(authorizedClient, principal);
		Object[] args = {
				authorizedClientData.clientRegistrationId,
				authorizedClientData.principalName,
				authorizedClientData.accessTokenType,
				authorizedClientData.accessTokenValue,		// TODO Encrypt
				authorizedClientData.accessTokenIssuedAt,
				authorizedClientData.accessTokenExpiresAt,
				authorizedClientData.accessTokenScopes,
				authorizedClientData.refreshTokenValue,		// TODO Encrypt
				authorizedClientData.refreshTokenIssuedAt
		};
		int[] argTypes = {
				Types.VARCHAR,
				Types.VARCHAR,
				Types.VARCHAR,
				Types.VARCHAR,
				Types.TIMESTAMP,
				Types.TIMESTAMP,
				Types.VARCHAR,
				Types.VARCHAR,
				Types.TIMESTAMP
		};
		PreparedStatementSetter pss = new ArgumentTypePreparedStatementSetter(args, argTypes);
		this.jdbcTemplate.update(SAVE_AUTHORIZED_CLIENT_SQL, pss);
	}

	@Transactional
	@Override
	public void removeAuthorizedClient(String clientRegistrationId, String principalName) {
		Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
		Assert.hasText(principalName, "principalName cannot be empty");

		Object[] args = {clientRegistrationId, principalName};
		int[] argTypes = {Types.VARCHAR, Types.VARCHAR};
		PreparedStatementSetter pss = new ArgumentTypePreparedStatementSetter(args, argTypes);
		this.jdbcTemplate.update(REMOVE_AUTHORIZED_CLIENT_SQL, pss);
	}

	private static OAuth2AuthorizedClientData mapData(ResultSet rs) throws SQLException {
		OAuth2AuthorizedClientData data = new OAuth2AuthorizedClientData();
		data.clientRegistrationId = rs.getString("client_registration_id");
		data.principalName = rs.getString("principal_name");
		data.accessTokenType = rs.getString("access_token_type");
		data.accessTokenValue = rs.getString("access_token_value");
		data.accessTokenIssuedAt = rs.getTimestamp("access_token_issued_at");
		data.accessTokenExpiresAt = rs.getTimestamp("access_token_expires_at");
		data.accessTokenScopes = rs.getString("access_token_scopes");
		data.refreshTokenValue = rs.getString("refresh_token_value");
		data.refreshTokenIssuedAt = rs.getTimestamp("refresh_token_issued_at");
		return data;
	}

	private static OAuth2AuthorizedClientData mapData(
			OAuth2AuthorizedClient authorizedClient, Authentication principal) {

		ClientRegistration clientRegistration = authorizedClient.getClientRegistration();
		OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
		OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();
		OAuth2AuthorizedClientData data = new OAuth2AuthorizedClientData();
		data.clientRegistrationId = clientRegistration.getRegistrationId();
		data.principalName = principal.getName();
		data.accessTokenType = accessToken.getTokenType().getValue();
		data.accessTokenValue = accessToken.getTokenValue();
		data.accessTokenIssuedAt = Timestamp.from(accessToken.getIssuedAt());
		data.accessTokenExpiresAt = Timestamp.from(accessToken.getExpiresAt());
		if (!CollectionUtils.isEmpty(accessToken.getScopes())) {
			data.accessTokenScopes = StringUtils.collectionToDelimitedString(accessToken.getScopes(), ",");
		}
		if (refreshToken != null) {
			data.refreshTokenValue = refreshToken.getTokenValue();
			if (refreshToken.getIssuedAt() != null) {
				data.refreshTokenIssuedAt = Timestamp.from(refreshToken.getIssuedAt());
			}
		}
		return data;
	}

	private static class OAuth2AuthorizedClientData {
		private String clientRegistrationId;
		private String principalName;
		private String accessTokenType;
		private String accessTokenValue;
		private java.sql.Timestamp accessTokenIssuedAt;
		private java.sql.Timestamp accessTokenExpiresAt;
		private String accessTokenScopes;
		private String refreshTokenValue;
		private java.sql.Timestamp refreshTokenIssuedAt;
	}
}
