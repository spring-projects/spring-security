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
import org.springframework.core.convert.converter.Converter;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.jdbc.core.ArgumentTypePreparedStatementSetter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
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
 * @see RowMapper
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
	protected RowMapper<OAuth2AuthorizedClientData> authorizedClientDataRowMapper;
	protected Converter<OAuth2AuthorizedClientData, OAuth2AuthorizedClient> authorizedClientDataConverter;
	protected Converter<OAuth2AuthorizedClientHolder, OAuth2AuthorizedClientData> authorizedClientConverter;

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
		this.authorizedClientDataRowMapper = new OAuth2AuthorizedClientDataRowMapper();
		this.authorizedClientDataConverter = new OAuth2AuthorizedClientDataConverter(clientRegistrationRepository);
		this.authorizedClientConverter = new OAuth2AuthorizedClientConverter();
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

		List<OAuth2AuthorizedClientData> result = this.jdbcTemplate.query(
				LOAD_AUTHORIZED_CLIENT_SQL, pss, this.authorizedClientDataRowMapper);

		return !result.isEmpty() ? (T) this.authorizedClientDataConverter.convert(result.get(0)) : null;
	}

	@Transactional
	@Override
	public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
		Assert.notNull(authorizedClient, "authorizedClient cannot be null");
		Assert.notNull(principal, "principal cannot be null");

		OAuth2AuthorizedClientData authorizedClientData = this.authorizedClientConverter.convert(
				new OAuth2AuthorizedClientHolder(authorizedClient, principal));
		Object[] args = {
				authorizedClientData.getClientRegistrationId(),
				authorizedClientData.getPrincipalName(),
				authorizedClientData.getAccessTokenType(),
				authorizedClientData.getAccessTokenValue(),
				authorizedClientData.getAccessTokenIssuedAt(),
				authorizedClientData.getAccessTokenExpiresAt(),
				authorizedClientData.getAccessTokenScopes(),
				authorizedClientData.getRefreshTokenValue(),
				authorizedClientData.getRefreshTokenIssuedAt()
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

	/**
	 * Sets the {@link RowMapper} used for mapping the current row in {@code java.sql.ResultSet} to {@link OAuth2AuthorizedClientData}.
	 * The default is {@link OAuth2AuthorizedClientDataRowMapper}.
	 *
	 * @param authorizedClientDataRowMapper the {@link RowMapper} used for mapping the current row in {@code java.sql.ResultSet} to {@link OAuth2AuthorizedClientData}
	 */
	public final void setAuthorizedClientDataRowMapper(RowMapper<OAuth2AuthorizedClientData> authorizedClientDataRowMapper) {
		Assert.notNull(authorizedClientDataRowMapper, "authorizedClientDataRowMapper cannot be null");
		this.authorizedClientDataRowMapper = authorizedClientDataRowMapper;
	}

	/**
	 * Sets the {@link Converter} used for converting {@link OAuth2AuthorizedClientData} to {@link OAuth2AuthorizedClient}.
	 * The default is {@link OAuth2AuthorizedClientDataConverter}.
	 *
	 * @param authorizedClientDataConverter the {@link Converter} used for converting {@link OAuth2AuthorizedClientData} to {@link OAuth2AuthorizedClient}
	 */
	public final void setAuthorizedClientDataConverter(Converter<OAuth2AuthorizedClientData, OAuth2AuthorizedClient> authorizedClientDataConverter) {
		Assert.notNull(authorizedClientDataConverter, "authorizedClientDataConverter cannot be null");
		this.authorizedClientDataConverter = authorizedClientDataConverter;
	}

	/**
	 * Sets the {@link Converter} used for converting {@link OAuth2AuthorizedClient} to {@link OAuth2AuthorizedClientData}.
	 * The default is {@link OAuth2AuthorizedClientConverter}.
	 *
	 * @param authorizedClientConverter the {@link Converter} used for converting {@link OAuth2AuthorizedClient} to {@link OAuth2AuthorizedClientData}
	 */
	public final void setAuthorizedClientConverter(Converter<OAuth2AuthorizedClientHolder, OAuth2AuthorizedClientData> authorizedClientConverter) {
		Assert.notNull(authorizedClientConverter, "authorizedClientConverter cannot be null");
		this.authorizedClientConverter = authorizedClientConverter;
	}

	/**
	 * The default {@link RowMapper} that maps the current row
	 * in {@code java.sql.ResultSet} to {@link OAuth2AuthorizedClientData}.
	 */
	public static class OAuth2AuthorizedClientDataRowMapper implements RowMapper<OAuth2AuthorizedClientData> {

		@Override
		public OAuth2AuthorizedClientData mapRow(ResultSet rs, int rowNum) throws SQLException {
			OAuth2AuthorizedClientData authorizedClientData = new OAuth2AuthorizedClientData();
			authorizedClientData.setClientRegistrationId(rs.getString("client_registration_id"));
			authorizedClientData.setPrincipalName(rs.getString("principal_name"));
			authorizedClientData.setAccessTokenType(rs.getString("access_token_type"));
			authorizedClientData.setAccessTokenValue(rs.getString("access_token_value"));
			authorizedClientData.setAccessTokenIssuedAt(rs.getTimestamp("access_token_issued_at"));
			authorizedClientData.setAccessTokenExpiresAt(rs.getTimestamp("access_token_expires_at"));
			authorizedClientData.setAccessTokenScopes(rs.getString("access_token_scopes"));
			authorizedClientData.setRefreshTokenValue(rs.getString("refresh_token_value"));
			authorizedClientData.setRefreshTokenIssuedAt(rs.getTimestamp("refresh_token_issued_at"));
			return authorizedClientData;
		}
	}

	/**
	 * The default {@link Converter} that converts {@link OAuth2AuthorizedClientData} to {@link OAuth2AuthorizedClient}.
	 */
	public static class OAuth2AuthorizedClientDataConverter implements Converter<OAuth2AuthorizedClientData, OAuth2AuthorizedClient> {
		protected final ClientRegistrationRepository clientRegistrationRepository;

		public OAuth2AuthorizedClientDataConverter(ClientRegistrationRepository clientRegistrationRepository) {
			Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
			this.clientRegistrationRepository = clientRegistrationRepository;
		}

		@Override
		public OAuth2AuthorizedClient convert(OAuth2AuthorizedClientData authorizedClientData) {
			ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(
					authorizedClientData.getClientRegistrationId());
			if (clientRegistration == null) {
				throw new DataRetrievalFailureException("The ClientRegistration with id '" +
						authorizedClientData.getClientRegistrationId() + "' exists in the data source, " +
						"however, it was not found in the ClientRegistrationRepository.");
			}

			OAuth2AccessToken.TokenType tokenType = null;
			if (OAuth2AccessToken.TokenType.BEARER.getValue().equalsIgnoreCase(authorizedClientData.getAccessTokenType())) {
				tokenType = OAuth2AccessToken.TokenType.BEARER;
			}
			String tokenValue = authorizedClientData.getAccessTokenValue();
			Instant issuedAt = authorizedClientData.getAccessTokenIssuedAt().toInstant();
			Instant expiresAt = authorizedClientData.getAccessTokenExpiresAt().toInstant();
			Set<String> scopes = Collections.emptySet();
			if (authorizedClientData.getAccessTokenScopes() != null) {
				scopes = StringUtils.commaDelimitedListToSet(authorizedClientData.getAccessTokenScopes());
			}
			OAuth2AccessToken accessToken = new OAuth2AccessToken(
					tokenType, tokenValue, issuedAt, expiresAt, scopes);

			OAuth2RefreshToken refreshToken = null;
			if (authorizedClientData.getRefreshTokenValue() != null) {
				tokenValue = authorizedClientData.getRefreshTokenValue();
				issuedAt = null;
				if (authorizedClientData.getRefreshTokenIssuedAt() != null) {
					issuedAt = authorizedClientData.getRefreshTokenIssuedAt().toInstant();
				}
				refreshToken = new OAuth2RefreshToken(tokenValue, issuedAt);
			}

			return new OAuth2AuthorizedClient(
					clientRegistration, authorizedClientData.getPrincipalName(), accessToken, refreshToken);
		}
	}

	/**
	 * The default {@link Converter} that converts {@link OAuth2AuthorizedClient} to {@link OAuth2AuthorizedClientData}.
	 */
	public static class OAuth2AuthorizedClientConverter implements Converter<OAuth2AuthorizedClientHolder, OAuth2AuthorizedClientData> {

		@Override
		public OAuth2AuthorizedClientData convert(OAuth2AuthorizedClientHolder authorizedClientHolder) {
			OAuth2AuthorizedClient authorizedClient = authorizedClientHolder.getAuthorizedClient();
			Authentication principal = authorizedClientHolder.getPrincipal();
			ClientRegistration clientRegistration = authorizedClient.getClientRegistration();
			OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
			OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();

			OAuth2AuthorizedClientData authorizedClientData = new OAuth2AuthorizedClientData();
			authorizedClientData.setClientRegistrationId(clientRegistration.getRegistrationId());
			authorizedClientData.setPrincipalName(principal.getName());
			authorizedClientData.setAccessTokenType(accessToken.getTokenType().getValue());
			authorizedClientData.setAccessTokenValue(accessToken.getTokenValue());
			authorizedClientData.setAccessTokenIssuedAt(Timestamp.from(accessToken.getIssuedAt()));
			authorizedClientData.setAccessTokenExpiresAt(Timestamp.from(accessToken.getExpiresAt()));
			if (!CollectionUtils.isEmpty(accessToken.getScopes())) {
				authorizedClientData.setAccessTokenScopes(StringUtils.collectionToDelimitedString(accessToken.getScopes(), ","));
			}
			if (refreshToken != null) {
				authorizedClientData.setRefreshTokenValue(refreshToken.getTokenValue());
				if (refreshToken.getIssuedAt() != null) {
					authorizedClientData.setRefreshTokenIssuedAt(Timestamp.from(refreshToken.getIssuedAt()));
				}
			}
			return authorizedClientData;
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

	/**
	 * The data (entity) representation of an {@link OAuth2AuthorizedClient}.
	 */
	public static class OAuth2AuthorizedClientData {
		private String clientRegistrationId;
		private String principalName;
		private String accessTokenType;
		private String accessTokenValue;
		private java.sql.Timestamp accessTokenIssuedAt;
		private java.sql.Timestamp accessTokenExpiresAt;
		private String accessTokenScopes;
		private String refreshTokenValue;
		private java.sql.Timestamp refreshTokenIssuedAt;

		/**
		 * Returns the {@link ClientRegistration#getRegistrationId()}.
		 *
		 * @return the {@link ClientRegistration#getRegistrationId()}
		 */
		public String getClientRegistrationId() {
			return this.clientRegistrationId;
		}

		/**
		 * Sets the {@link ClientRegistration#getRegistrationId()}.
		 *
		 * @param clientRegistrationId the {@link ClientRegistration#getRegistrationId()}
		 */
		public void setClientRegistrationId(String clientRegistrationId) {
			this.clientRegistrationId = clientRegistrationId;
		}

		/**
		 * Returns the name of the End-User {@code Principal} (Resource Owner).
		 *
		 * @return the name of the End-User {@code Principal} (Resource Owner)
		 */
		public String getPrincipalName() {
			return this.principalName;
		}

		/**
		 * Sets the name of the End-User {@code Principal} (Resource Owner).
		 *
		 * @param principalName the name of the End-User {@code Principal} (Resource Owner).
		 */
		public void setPrincipalName(String principalName) {
			this.principalName = principalName;
		}

		/**
		 * Returns the {@link OAuth2AccessToken.TokenType#getValue()}.
		 *
		 * @return the {@link OAuth2AccessToken.TokenType#getValue()}
		 */
		public String getAccessTokenType() {
			return this.accessTokenType;
		}

		/**
		 * Sets the {@link OAuth2AccessToken.TokenType#getValue()}.
		 *
		 * @param accessTokenType the {@link OAuth2AccessToken.TokenType#getValue()}
		 */
		public void setAccessTokenType(String accessTokenType) {
			this.accessTokenType = accessTokenType;
		}

		/**
		 * Returns the {@link OAuth2AccessToken#getTokenValue()}.
		 *
		 * @return the {@link OAuth2AccessToken#getTokenValue()}
		 */
		public String getAccessTokenValue() {
			return this.accessTokenValue;
		}

		/**
		 * Sets the {@link OAuth2AccessToken#getTokenValue()}.
		 *
		 * @param accessTokenValue the {@link OAuth2AccessToken#getTokenValue()}
		 */
		public void setAccessTokenValue(String accessTokenValue) {
			this.accessTokenValue = accessTokenValue;
		}

		/**
		 * Returns the {@link OAuth2AccessToken#getIssuedAt()}.
		 *
		 * @return the {@link OAuth2AccessToken#getIssuedAt()}
		 */
		public Timestamp getAccessTokenIssuedAt() {
			return this.accessTokenIssuedAt;
		}

		/**
		 * Sets the {@link OAuth2AccessToken#getIssuedAt()}.
		 *
		 * @param accessTokenIssuedAt the {@link OAuth2AccessToken#getIssuedAt()}
		 */
		public void setAccessTokenIssuedAt(Timestamp accessTokenIssuedAt) {
			this.accessTokenIssuedAt = accessTokenIssuedAt;
		}

		/**
		 * Returns the {@link OAuth2AccessToken#getExpiresAt()}.
		 *
		 * @return the {@link OAuth2AccessToken#getExpiresAt()}
		 */
		public Timestamp getAccessTokenExpiresAt() {
			return this.accessTokenExpiresAt;
		}

		/**
		 * Sets the {@link OAuth2AccessToken#getExpiresAt()}.
		 *
		 * @param accessTokenExpiresAt the {@link OAuth2AccessToken#getExpiresAt()}
		 */
		public void setAccessTokenExpiresAt(Timestamp accessTokenExpiresAt) {
			this.accessTokenExpiresAt = accessTokenExpiresAt;
		}

		/**
		 * Returns the {@link OAuth2AccessToken#getScopes()}.
		 *
		 * @return the {@link OAuth2AccessToken#getScopes()}
		 */
		public String getAccessTokenScopes() {
			return this.accessTokenScopes;
		}

		/**
		 * Sets the {@link OAuth2AccessToken#getScopes()}.
		 *
		 * @param accessTokenScopes the {@link OAuth2AccessToken#getScopes()}
		 */
		public void setAccessTokenScopes(String accessTokenScopes) {
			this.accessTokenScopes = accessTokenScopes;
		}

		/**
		 * Returns the {@link OAuth2RefreshToken#getTokenValue()}.
		 *
		 * @return the {@link OAuth2RefreshToken#getTokenValue()}
		 */
		public String getRefreshTokenValue() {
			return this.refreshTokenValue;
		}

		/**
		 * Sets the {@link OAuth2RefreshToken#getTokenValue()}.
		 *
		 * @param refreshTokenValue the {@link OAuth2RefreshToken#getTokenValue()}
		 */
		public void setRefreshTokenValue(String refreshTokenValue) {
			this.refreshTokenValue = refreshTokenValue;
		}

		/**
		 * Returns the {@link OAuth2RefreshToken#getIssuedAt()}.
		 *
		 * @return the {@link OAuth2RefreshToken#getIssuedAt()}
		 */
		public Timestamp getRefreshTokenIssuedAt() {
			return this.refreshTokenIssuedAt;
		}

		/**
		 * Sets the {@link OAuth2RefreshToken#getIssuedAt()}.
		 *
		 * @param refreshTokenIssuedAt the {@link OAuth2RefreshToken#getIssuedAt()}
		 */
		public void setRefreshTokenIssuedAt(Timestamp refreshTokenIssuedAt) {
			this.refreshTokenIssuedAt = refreshTokenIssuedAt;
		}
	}
}
