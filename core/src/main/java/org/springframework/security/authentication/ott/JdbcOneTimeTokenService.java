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

package org.springframework.security.authentication.ott;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.jdbc.core.ArgumentPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.SqlParameterValue;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.scheduling.support.CronTrigger;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 *
 * A JDBC implementation of an {@link OneTimeTokenService} that uses a
 * {@link JdbcOperations} for {@link OneTimeToken} persistence.
 *
 * <p>
 * <b>NOTE:</b> This {@code JdbcOneTimeTokenService} depends on the table definition
 * described in
 * "classpath:org/springframework/security/core/ott/jdbc/one-time-tokens-schema.sql" and
 * therefore MUST be defined in the database schema.
 *
 * @author Max Batischev
 * @since 6.4
 */
public final class JdbcOneTimeTokenService implements OneTimeTokenService, DisposableBean, InitializingBean {

	private final Log logger = LogFactory.getLog(getClass());

	private final JdbcOperations jdbcOperations;

	private Function<OneTimeToken, List<SqlParameterValue>> oneTimeTokenParametersMapper = new OneTimeTokenParametersMapper();

	private RowMapper<OneTimeToken> oneTimeTokenRowMapper = new OneTimeTokenRowMapper();

	private Clock clock = Clock.systemUTC();

	private ThreadPoolTaskScheduler taskScheduler;

	private static final String DEFAULT_CLEANUP_CRON = "@hourly";

	private static final String TABLE_NAME = "one_time_tokens";

	// @formatter:off
	private static final String COLUMN_NAMES = "token_value, "
			+ "username, "
			+ "expires_at";
	// @formatter:on

	// @formatter:off
	private static final String SAVE_ONE_TIME_TOKEN_SQL = "INSERT INTO " + TABLE_NAME
			+ " (" + COLUMN_NAMES + ") VALUES (?, ?, ?)";
	// @formatter:on

	private static final String FILTER = "token_value = ?";

	private static final String DELETE_ONE_TIME_TOKEN_SQL = "DELETE FROM " + TABLE_NAME + " WHERE " + FILTER;

	// @formatter:off
	private static final String SELECT_ONE_TIME_TOKEN_SQL = "SELECT " + COLUMN_NAMES
			+ " FROM " + TABLE_NAME
			+ " WHERE " + FILTER;
	// @formatter:on

	// @formatter:off
	private static final String DELETE_ONE_TIME_TOKENS_BY_EXPIRY_TIME_QUERY = "DELETE FROM "
			+ TABLE_NAME
			+ " WHERE expires_at < ?";
	// @formatter:on

	/**
	 * Constructs a {@code JdbcOneTimeTokenService} using the provide parameters.
	 * @param jdbcOperations the JDBC operations
	 */
	public JdbcOneTimeTokenService(JdbcOperations jdbcOperations) {
		Assert.notNull(jdbcOperations, "jdbcOperations cannot be null");
		this.jdbcOperations = jdbcOperations;
		this.taskScheduler = createTaskScheduler(DEFAULT_CLEANUP_CRON);
	}

	/**
	 * Sets the chron expression used for cleaning up expired tokens. The default is to
	 * run hourly.
	 *
	 * For more advanced use cases the cleanupCron may be set to null which will disable
	 * the built-in cleanup. Users can then invoke {@link #cleanupExpiredTokens()} using
	 * custom logic.
	 * @param cleanupCron the chron expression passed to {@link CronTrigger} used for
	 * determining how frequent to perform cleanup. The default is "@hourly".
	 * @see CronTrigger
	 * @see #cleanupExpiredTokens()
	 */
	public void setCleanupCron(String cleanupCron) {
		this.taskScheduler = createTaskScheduler(cleanupCron);
	}

	@Override
	public OneTimeToken generate(GenerateOneTimeTokenRequest request) {
		Assert.notNull(request, "generateOneTimeTokenRequest cannot be null");
		String token = UUID.randomUUID().toString();
		Instant fiveMinutesFromNow = this.clock.instant().plus(Duration.ofMinutes(5));
		OneTimeToken oneTimeToken = new DefaultOneTimeToken(token, request.getUsername(), fiveMinutesFromNow);
		insertOneTimeToken(oneTimeToken);
		return oneTimeToken;
	}

	private void insertOneTimeToken(OneTimeToken oneTimeToken) {
		List<SqlParameterValue> parameters = this.oneTimeTokenParametersMapper.apply(oneTimeToken);
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());
		this.jdbcOperations.update(SAVE_ONE_TIME_TOKEN_SQL, pss);
	}

	@Override
	public OneTimeToken consume(OneTimeTokenAuthenticationToken authenticationToken) {
		Assert.notNull(authenticationToken, "authenticationToken cannot be null");

		List<OneTimeToken> tokens = selectOneTimeToken(authenticationToken);
		if (CollectionUtils.isEmpty(tokens)) {
			return null;
		}
		OneTimeToken token = tokens.get(0);
		deleteOneTimeToken(token);
		if (isExpired(token)) {
			return null;
		}
		return token;
	}

	private boolean isExpired(OneTimeToken ott) {
		return this.clock.instant().isAfter(ott.getExpiresAt());
	}

	private List<OneTimeToken> selectOneTimeToken(OneTimeTokenAuthenticationToken authenticationToken) {
		List<SqlParameterValue> parameters = List
			.of(new SqlParameterValue(Types.VARCHAR, authenticationToken.getTokenValue()));
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());
		return this.jdbcOperations.query(SELECT_ONE_TIME_TOKEN_SQL, pss, this.oneTimeTokenRowMapper);
	}

	private void deleteOneTimeToken(OneTimeToken oneTimeToken) {
		List<SqlParameterValue> parameters = List
			.of(new SqlParameterValue(Types.VARCHAR, oneTimeToken.getTokenValue()));
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());
		this.jdbcOperations.update(DELETE_ONE_TIME_TOKEN_SQL, pss);
	}

	private ThreadPoolTaskScheduler createTaskScheduler(String cleanupCron) {
		if (cleanupCron == null) {
			return null;
		}
		ThreadPoolTaskScheduler taskScheduler = new ThreadPoolTaskScheduler();
		taskScheduler.setThreadNamePrefix("spring-one-time-tokens-");
		taskScheduler.initialize();
		taskScheduler.schedule(this::cleanupExpiredTokens, new CronTrigger(cleanupCron));
		return taskScheduler;
	}

	public void cleanupExpiredTokens() {
		List<SqlParameterValue> parameters = List
			.of(new SqlParameterValue(Types.TIMESTAMP, Timestamp.from(Instant.now())));
		PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters.toArray());
		int deletedCount = this.jdbcOperations.update(DELETE_ONE_TIME_TOKENS_BY_EXPIRY_TIME_QUERY, pss);
		if (this.logger.isDebugEnabled()) {
			this.logger.debug("Cleaned up " + deletedCount + " expired tokens");
		}
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		this.taskScheduler.afterPropertiesSet();
	}

	@Override
	public void destroy() throws Exception {
		if (this.taskScheduler != null) {
			this.taskScheduler.shutdown();
		}
	}

	/**
	 * Sets the {@link Clock} used when generating one-time token and checking token
	 * expiry.
	 * @param clock the clock
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock cannot be null");
		this.clock = clock;
	}

	/**
	 * The default {@code Function} that maps {@link OneTimeToken} to a {@code List} of
	 * {@link SqlParameterValue}.
	 *
	 * @author Max Batischev
	 * @since 6.4
	 */
	private static class OneTimeTokenParametersMapper implements Function<OneTimeToken, List<SqlParameterValue>> {

		@Override
		public List<SqlParameterValue> apply(OneTimeToken oneTimeToken) {
			List<SqlParameterValue> parameters = new ArrayList<>();
			parameters.add(new SqlParameterValue(Types.VARCHAR, oneTimeToken.getTokenValue()));
			parameters.add(new SqlParameterValue(Types.VARCHAR, oneTimeToken.getUsername()));
			parameters.add(new SqlParameterValue(Types.TIMESTAMP, Timestamp.from(oneTimeToken.getExpiresAt())));
			return parameters;
		}

	}

	/**
	 * The default {@link RowMapper} that maps the current row in
	 * {@code java.sql.ResultSet} to {@link OneTimeToken}.
	 *
	 * @author Max Batischev
	 * @since 6.4
	 */
	private static class OneTimeTokenRowMapper implements RowMapper<OneTimeToken> {

		@Override
		public OneTimeToken mapRow(ResultSet rs, int rowNum) throws SQLException {
			String tokenValue = rs.getString("token_value");
			String userName = rs.getString("username");
			Instant expiresAt = rs.getTimestamp("expires_at").toInstant();
			return new DefaultOneTimeToken(tokenValue, userName, expiresAt);
		}

	}

}
