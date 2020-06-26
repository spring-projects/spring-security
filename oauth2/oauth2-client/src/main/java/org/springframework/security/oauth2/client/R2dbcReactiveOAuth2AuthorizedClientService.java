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

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.function.BiFunction;
import java.util.function.Function;

import io.r2dbc.spi.Row;
import io.r2dbc.spi.RowMetadata;
import reactor.core.publisher.Mono;

import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.r2dbc.core.DatabaseClient.GenericExecuteSpec;
import org.springframework.r2dbc.core.Parameter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * A R2DBC implementation of {@link ReactiveOAuth2AuthorizedClientService} that uses a
 * {@link DatabaseClient} for {@link OAuth2AuthorizedClient} persistence.
 *
 * <p>
 * <b>NOTE:</b> This {@code ReactiveOAuth2AuthorizedClientService} depends on the table
 * definition described in
 * "classpath:org/springframework/security/oauth2/client/oauth2-client-schema.sql" and
 * therefore MUST be defined in the database schema.
 *
 * @author Ovidiu Popa
 * @since 5.5
 * @see ReactiveOAuth2AuthorizedClientService
 * @see OAuth2AuthorizedClient
 * @see DatabaseClient
 *
 */
public class R2dbcReactiveOAuth2AuthorizedClientService implements ReactiveOAuth2AuthorizedClientService {

	// @formatter:off
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
	// @formatter:on

	private static final String TABLE_NAME = "oauth2_authorized_client";

	private static final String PK_FILTER = "client_registration_id = :clientRegistrationId AND principal_name = :principalName";

	// @formatter:off
	private static final String LOAD_AUTHORIZED_CLIENT_SQL = "SELECT " + COLUMN_NAMES + " FROM " + TABLE_NAME
			+ " WHERE " + PK_FILTER;
	// @formatter:on

	// @formatter:off
	private static final String SAVE_AUTHORIZED_CLIENT_SQL = "INSERT INTO " + TABLE_NAME + " (" + COLUMN_NAMES + ")" +
			"VALUES (:clientRegistrationId, :principalName, :accessTokenType, :accessTokenValue," +
				" :accessTokenIssuedAt, :accessTokenExpiresAt, :accessTokenScopes, :refreshTokenValue," +
				" :refreshTokenIssuedAt)";
	// @formatter:on

	private static final String REMOVE_AUTHORIZED_CLIENT_SQL = "DELETE FROM " + TABLE_NAME + " WHERE " + PK_FILTER;

	// @formatter:off
	private static final String UPDATE_AUTHORIZED_CLIENT_SQL = "UPDATE " + TABLE_NAME +
			" SET access_token_type = :accessTokenType, " +
			" access_token_value = :accessTokenValue, " +
			" access_token_issued_at = :accessTokenIssuedAt," +
			" access_token_expires_at = :accessTokenExpiresAt, " +
			" access_token_scopes = :accessTokenScopes," +
			" refresh_token_value = :refreshTokenValue, " +
			" refresh_token_issued_at = :refreshTokenIssuedAt" +
			" WHERE " +
			PK_FILTER;
	// @formatter:on

	protected final DatabaseClient databaseClient;

	protected Function<OAuth2AuthorizedClientHolder, Map<String, Parameter>> authorizedClientParametersMapper;

	protected BiFunction<Row, RowMetadata, OAuth2AuthorizedClientHolder> authorizedClientRowMapper;

	private ReactiveClientRegistrationRepository clientRegistrationRepository;

	/**
	 * Constructs a {@code R2dbcReactiveOAuth2AuthorizedClientService} using the provided
	 * parameters.
	 * @param databaseClient the DatabaseClient
	 * @param clientRegistrationRepository the repository of client registrations
	 */
	public R2dbcReactiveOAuth2AuthorizedClientService(DatabaseClient databaseClient,
			ReactiveClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(databaseClient, "databaseClient cannot be null");
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.databaseClient = databaseClient;
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizedClientParametersMapper = new OAuth2AuthorizedClientParametersMapper();
		this.authorizedClientRowMapper = new OAuth2AuthorizedClientRowMapper();
	}

	@Override
	@SuppressWarnings("unchecked")
	public <T extends OAuth2AuthorizedClient> Mono<T> loadAuthorizedClient(String clientRegistrationId,
			String principalName) {
		Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
		Assert.hasText(principalName, "principalName cannot be empty");

		return (Mono<T>) this.databaseClient.sql(LOAD_AUTHORIZED_CLIENT_SQL)
				.bind("clientRegistrationId", clientRegistrationId).bind("principalName", principalName)
				.map(this.authorizedClientRowMapper::apply).first().flatMap(this::getOauth2AuthorizedClient);
	}

	private Mono<OAuth2AuthorizedClient> getOauth2AuthorizedClient(
			OAuth2AuthorizedClientHolder oAuth2AuthorizedClientHolder) {
		return this.clientRegistrationRepository
				.findByRegistrationId(oAuth2AuthorizedClientHolder.getClientRegistrationId())
				.switchIfEmpty(Mono
						.error(dataRetrievalFailureException(oAuth2AuthorizedClientHolder.getClientRegistrationId())))
				.map((clientRegistration) -> new OAuth2AuthorizedClient(clientRegistration,
						oAuth2AuthorizedClientHolder.getPrincipalName(), oAuth2AuthorizedClientHolder.getAccessToken(),
						oAuth2AuthorizedClientHolder.getRefreshToken()));
	}

	private Throwable dataRetrievalFailureException(String clientRegistrationId) {
		return new DataRetrievalFailureException("The ClientRegistration with id '" + clientRegistrationId
				+ "' exists in the data source, " + "however, it was not found in the ClientRegistrationRepository.");
	}

	@Override
	public Mono<Void> saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
		Assert.notNull(authorizedClient, "authorizedClient cannot be null");
		Assert.notNull(principal, "principal cannot be null");
		return this
				.loadAuthorizedClient(authorizedClient.getClientRegistration().getRegistrationId(), principal.getName())
				.flatMap((dbAuthorizedClient) -> updateAuthorizedClient(authorizedClient, principal))
				.switchIfEmpty(Mono.defer(() -> insertAuthorizedClient(authorizedClient, principal))).then();
	}

	private Mono<Integer> updateAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
		GenericExecuteSpec executeSpec = this.databaseClient.sql(UPDATE_AUTHORIZED_CLIENT_SQL);
		for (Entry<String, Parameter> entry : this.authorizedClientParametersMapper
				.apply(new OAuth2AuthorizedClientHolder(authorizedClient, principal)).entrySet()) {
			executeSpec = executeSpec.bind(entry.getKey(), entry.getValue());
		}
		return executeSpec.fetch().rowsUpdated();
	}

	private Mono<Integer> insertAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
		GenericExecuteSpec executeSpec = this.databaseClient.sql(SAVE_AUTHORIZED_CLIENT_SQL);
		for (Entry<String, Parameter> entry : this.authorizedClientParametersMapper
				.apply(new OAuth2AuthorizedClientHolder(authorizedClient, principal)).entrySet()) {
			executeSpec = executeSpec.bind(entry.getKey(), entry.getValue());
		}
		return executeSpec.fetch().rowsUpdated();
	}

	@Override
	public Mono<Void> removeAuthorizedClient(String clientRegistrationId, String principalName) {
		Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
		Assert.hasText(principalName, "principalName cannot be empty");
		return this.databaseClient.sql(REMOVE_AUTHORIZED_CLIENT_SQL).bind("clientRegistrationId", clientRegistrationId)
				.bind("principalName", principalName).then();
	}

	/**
	 * Sets the {@code Function} used for mapping {@link OAuth2AuthorizedClientHolder} to
	 * a {@code Map} of {@link String} and {@link Parameter}. The default is
	 * {@link OAuth2AuthorizedClientParametersMapper}.
	 * @param authorizedClientParametersMapper the {@code Function} used for mapping
	 * {@link OAuth2AuthorizedClientHolder} to a {@code Map} of {@link String} and
	 * {@link Parameter}
	 */
	public void setAuthorizedClientParametersMapper(
			Function<OAuth2AuthorizedClientHolder, Map<String, Parameter>> authorizedClientParametersMapper) {
		Assert.notNull(authorizedClientParametersMapper, "authorizedClientParametersMapper cannot be null");
		this.authorizedClientParametersMapper = authorizedClientParametersMapper;
	}

	/**
	 * Sets the {@link BiFunction} used for mapping the current {@code io.r2dbc.spi.Row}
	 * to {@link OAuth2AuthorizedClientHolder}. The default is
	 * {@link OAuth2AuthorizedClientRowMapper}.
	 * @param authorizedClientRowMapper the {@link BiFunction} used for mapping the
	 * current {@code io.r2dbc.spi.Row} to {@link OAuth2AuthorizedClientHolder}
	 */
	public void setAuthorizedClientRowMapper(
			BiFunction<Row, RowMetadata, OAuth2AuthorizedClientHolder> authorizedClientRowMapper) {
		Assert.notNull(authorizedClientRowMapper, "authorizedClientRowMapper cannot be null");
		this.authorizedClientRowMapper = authorizedClientRowMapper;
	}

	/**
	 * A holder for an {@link OAuth2AuthorizedClient} data and End-User
	 * {@link Authentication} (Resource Owner).
	 */
	public static final class OAuth2AuthorizedClientHolder {

		private final String clientRegistrationId;

		private final String principalName;

		private final OAuth2AccessToken accessToken;

		private final OAuth2RefreshToken refreshToken;

		/**
		 * Constructs an {@code OAuth2AuthorizedClientHolder} using the provided
		 * parameters.
		 * @param authorizedClient the authorized client
		 * @param principal the End-User {@link Authentication} (Resource Owner)
		 */
		public OAuth2AuthorizedClientHolder(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
			Assert.notNull(authorizedClient, "authorizedClient cannot be null");
			Assert.notNull(principal, "principal cannot be null");
			this.clientRegistrationId = authorizedClient.getClientRegistration().getRegistrationId();
			this.principalName = principal.getName();
			this.accessToken = authorizedClient.getAccessToken();
			this.refreshToken = authorizedClient.getRefreshToken();
		}

		/**
		 * Constructs an {@code OAuth2AuthorizedClientHolder} using the provided
		 * parameters.
		 * @param clientRegistrationId the client registration id
		 * @param principalName the principal name of the End-User (Resource Owner)
		 * @param accessToken the access token
		 * @param refreshToken the refresh token
		 */
		public OAuth2AuthorizedClientHolder(String clientRegistrationId, String principalName,
				OAuth2AccessToken accessToken, OAuth2RefreshToken refreshToken) {
			this.clientRegistrationId = clientRegistrationId;
			this.principalName = principalName;
			this.accessToken = accessToken;
			this.refreshToken = refreshToken;
		}

		public String getClientRegistrationId() {
			return this.clientRegistrationId;
		}

		public String getPrincipalName() {
			return this.principalName;
		}

		public OAuth2AccessToken getAccessToken() {
			return this.accessToken;
		}

		public OAuth2RefreshToken getRefreshToken() {
			return this.refreshToken;
		}

	}

	/**
	 * The default {@code Function} that maps {@link OAuth2AuthorizedClientHolder} to a a
	 * {@code Map} of {@link String} and {@link Parameter}
	 */
	public static class OAuth2AuthorizedClientParametersMapper
			implements Function<OAuth2AuthorizedClientHolder, Map<String, Parameter>> {

		@Override
		public Map<String, Parameter> apply(OAuth2AuthorizedClientHolder authorizedClientHolder) {

			final Map<String, Parameter> parameters = new HashMap<>();

			final OAuth2AccessToken accessToken = authorizedClientHolder.getAccessToken();
			final OAuth2RefreshToken refreshToken = authorizedClientHolder.getRefreshToken();

			parameters.put("clientRegistrationId",
					Parameter.fromOrEmpty(authorizedClientHolder.getClientRegistrationId(), String.class));
			parameters.put("principalName",
					Parameter.fromOrEmpty(authorizedClientHolder.getPrincipalName(), String.class));
			parameters.put("accessTokenType",
					Parameter.fromOrEmpty(accessToken.getTokenType().getValue(), String.class));
			parameters.put("accessTokenValue", Parameter.fromOrEmpty(
					ByteBuffer.wrap(accessToken.getTokenValue().getBytes(StandardCharsets.UTF_8)), ByteBuffer.class));
			parameters.put("accessTokenIssuedAt", Parameter.fromOrEmpty(
					LocalDateTime.ofInstant(accessToken.getIssuedAt(), ZoneOffset.UTC), LocalDateTime.class));
			parameters.put("accessTokenExpiresAt", Parameter.fromOrEmpty(
					LocalDateTime.ofInstant(accessToken.getExpiresAt(), ZoneOffset.UTC), LocalDateTime.class));
			String accessTokenScopes = null;
			if (!CollectionUtils.isEmpty(accessToken.getScopes())) {
				accessTokenScopes = StringUtils.collectionToDelimitedString(accessToken.getScopes(), ",");

			}
			parameters.put("accessTokenScopes", Parameter.fromOrEmpty(accessTokenScopes, String.class));
			ByteBuffer refreshTokenValue = null;
			LocalDateTime refreshTokenIssuedAt = null;
			if (refreshToken != null) {
				refreshTokenValue = ByteBuffer.wrap(refreshToken.getTokenValue().getBytes(StandardCharsets.UTF_8));
				if (refreshToken.getIssuedAt() != null) {
					refreshTokenIssuedAt = LocalDateTime.ofInstant(refreshToken.getIssuedAt(), ZoneOffset.UTC);
				}

			}

			parameters.put("refreshTokenValue", Parameter.fromOrEmpty(refreshTokenValue, ByteBuffer.class));
			parameters.put("refreshTokenIssuedAt", Parameter.fromOrEmpty(refreshTokenIssuedAt, LocalDateTime.class));
			return parameters;
		}

	}

	/**
	 * The default {@link BiFunction} that maps the current {@code io.r2dbc.spi.Row} to a
	 * {@link OAuth2AuthorizedClientHolder}.
	 */
	public static class OAuth2AuthorizedClientRowMapper
			implements BiFunction<Row, RowMetadata, OAuth2AuthorizedClientHolder> {

		@Override
		public OAuth2AuthorizedClientHolder apply(Row row, RowMetadata rowMetadata) {

			String dbClientRegistrationId = row.get("client_registration_id", String.class);
			OAuth2AccessToken.TokenType tokenType = null;
			if (OAuth2AccessToken.TokenType.BEARER.getValue()
					.equalsIgnoreCase(row.get("access_token_type", String.class))) {
				tokenType = OAuth2AccessToken.TokenType.BEARER;
			}
			String tokenValue = new String(row.get("access_token_value", ByteBuffer.class).array(),
					StandardCharsets.UTF_8);
			Instant issuedAt = row.get("access_token_issued_at", LocalDateTime.class).toInstant(ZoneOffset.UTC);
			Instant expiresAt = row.get("access_token_expires_at", LocalDateTime.class).toInstant(ZoneOffset.UTC);

			Set<String> scopes = Collections.emptySet();
			String accessTokenScopes = row.get("access_token_scopes", String.class);
			if (accessTokenScopes != null) {
				scopes = StringUtils.commaDelimitedListToSet(accessTokenScopes);
			}
			final OAuth2AccessToken accessToken = new OAuth2AccessToken(tokenType, tokenValue, issuedAt, expiresAt,
					scopes);

			OAuth2RefreshToken refreshToken = null;
			ByteBuffer refreshTokenValue = row.get("refresh_token_value", ByteBuffer.class);
			if (refreshTokenValue != null) {
				tokenValue = new String(refreshTokenValue.array(), StandardCharsets.UTF_8);
				issuedAt = null;
				LocalDateTime refreshTokenIssuedAt = row.get("refresh_token_issued_at", LocalDateTime.class);
				if (refreshTokenIssuedAt != null) {
					issuedAt = refreshTokenIssuedAt.toInstant(ZoneOffset.UTC);
				}
				refreshToken = new OAuth2RefreshToken(tokenValue, issuedAt);
			}

			String dbPrincipalName = row.get("principal_name", String.class);
			return new OAuth2AuthorizedClientHolder(dbClientRegistrationId, dbPrincipalName, accessToken, refreshToken);
		}

	}

}
