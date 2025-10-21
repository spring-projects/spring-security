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

package org.springframework.security.web.authentication.rememberme;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Date;

import org.jspecify.annotations.Nullable;

import org.springframework.core.log.LogMessage;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.support.JdbcDaoSupport;

/**
 * JDBC based persistent login token repository implementation.
 *
 * @author Luke Taylor
 * @since 2.0
 */
public class JdbcTokenRepositoryImpl extends JdbcDaoSupport implements PersistentTokenRepository {

	/** Default SQL for creating the database table to store the tokens */
	public static final String CREATE_TABLE_SQL = "create table persistent_logins (username varchar(64) not null, series varchar(64) primary key, "
			+ "token varchar(64) not null, last_used timestamp not null)";

	/** The default SQL used by the <tt>getTokenBySeries</tt> query */
	public static final String DEF_TOKEN_BY_SERIES_SQL = "select username,series,token,last_used from persistent_logins where series = ?";

	/** The default SQL used by <tt>createNewToken</tt> */
	public static final String DEF_INSERT_TOKEN_SQL = "insert into persistent_logins (username, series, token, last_used) values(?,?,?,?)";

	/** The default SQL used by <tt>updateToken</tt> */
	public static final String DEF_UPDATE_TOKEN_SQL = "update persistent_logins set token = ?, last_used = ? where series = ?";

	/** The default SQL used by <tt>removeUserTokens</tt> */
	public static final String DEF_REMOVE_USER_TOKENS_SQL = "delete from persistent_logins where username = ?";

	private String tokensBySeriesSql = DEF_TOKEN_BY_SERIES_SQL;

	private String insertTokenSql = DEF_INSERT_TOKEN_SQL;

	private String updateTokenSql = DEF_UPDATE_TOKEN_SQL;

	private String removeUserTokensSql = DEF_REMOVE_USER_TOKENS_SQL;

	private boolean createTableOnStartup;

	@Override
	protected void initDao() {
		if (this.createTableOnStartup) {
			getTemplate().execute(CREATE_TABLE_SQL);
		}
	}

	@Override
	public void createNewToken(PersistentRememberMeToken token) {
		getTemplate().update(this.insertTokenSql, token.getUsername(), token.getSeries(), token.getTokenValue(),
				token.getDate());
	}

	@Override
	public void updateToken(String series, String tokenValue, Date lastUsed) {
		getTemplate().update(this.updateTokenSql, tokenValue, lastUsed, series);
	}

	/**
	 * Loads the token data for the supplied series identifier.
	 *
	 * If an error occurs, it will be reported and null will be returned (since the result
	 * should just be a failed persistent login).
	 * @param seriesId
	 * @return the token matching the series, or null if no match found or an exception
	 * occurred.
	 */
	@Override
	public @Nullable PersistentRememberMeToken getTokenForSeries(String seriesId) {
		try {
			return getTemplate().queryForObject(this.tokensBySeriesSql, this::createRememberMeToken, seriesId);
		}
		catch (EmptyResultDataAccessException ex) {
			this.logger.debug(LogMessage.format("Querying token for series '%s' returned no results.", seriesId), ex);
		}
		catch (IncorrectResultSizeDataAccessException ex) {
			this.logger.error(LogMessage.format(
					"Querying token for series '%s' returned more than one value. Series" + " should be unique",
					seriesId));
		}
		catch (DataAccessException ex) {
			this.logger.error("Failed to load token for series " + seriesId, ex);
		}
		return null;
	}

	private PersistentRememberMeToken createRememberMeToken(ResultSet rs, int rowNum) throws SQLException {
		return new PersistentRememberMeToken(rs.getString(1), rs.getString(2), rs.getString(3), rs.getTimestamp(4));
	}

	@Override
	public void removeUserTokens(String username) {
		getTemplate().update(this.removeUserTokensSql, username);
	}

	/**
	 * Intended for convenience in debugging. Will create the persistent_tokens database
	 * table when the class is initialized during the initDao method.
	 * @param createTableOnStartup set to true to execute the
	 */
	public void setCreateTableOnStartup(boolean createTableOnStartup) {
		this.createTableOnStartup = createTableOnStartup;
	}

	private JdbcTemplate getTemplate() {
		@Nullable JdbcTemplate result = super.getJdbcTemplate();
		if (result == null) {
			throw new IllegalStateException("JdbcTemplate was removed");
		}
		return result;
	}

}
