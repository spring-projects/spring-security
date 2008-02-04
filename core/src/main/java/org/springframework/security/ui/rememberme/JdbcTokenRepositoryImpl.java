package org.springframework.security.ui.rememberme;

import org.springframework.dao.DataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.core.SqlParameter;
import org.springframework.jdbc.core.support.JdbcDaoSupport;
import org.springframework.jdbc.object.MappingSqlQuery;
import org.springframework.jdbc.object.SqlUpdate;

import javax.sql.DataSource;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.Date;

/**
 * JDBC based persistent login token repository implementation.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
public class JdbcTokenRepositoryImpl extends JdbcDaoSupport implements PersistentTokenRepository {
    //~ Static fields/initializers =====================================================================================

    /** Default SQL for creating the database table to store the tokens */
    public static final String CREATE_TABLE_SQL =
            "create table persistent_logins (username varchar(64) not null, series varchar(64) primary key, " +
                    "token varchar(64) not null, last_used timestamp not null)";
    /** The default SQL used by the <tt>getTokenBySeries</tt> query */
    public static final String DEF_TOKEN_BY_SERIES_SQL =
            "select username,series,token,last_used from persistent_logins where series = ?";
    /** The default SQL used by <tt>createNewToken</tt> */
    public static final String DEF_INSERT_TOKEN_SQL =
            "insert into persistent_logins (username, series, token, last_used) values(?,?,?,?)";
    /** The default SQL used by <tt>updateToken</tt> */
    public static final String DEF_UPDATE_TOKEN_SQL =
            "update persistent_logins set token = ?, last_used = ? where series = ?";
    /** The default SQL used by <tt>removeUserTokens</tt> */
    public static final String DEF_REMOVE_USER_TOKENS_SQL =
            "delete from persistent_logins where username = ?";

    //~ Instance fields ================================================================================================

    private String tokensBySeriesSql = DEF_TOKEN_BY_SERIES_SQL;
    private String insertTokenSql = DEF_INSERT_TOKEN_SQL;
    private String updateTokenSql = DEF_UPDATE_TOKEN_SQL;
    private String removeUserTokensSql = DEF_REMOVE_USER_TOKENS_SQL;
    private boolean createTableOnStartup;

    protected MappingSqlQuery tokensBySeriesMapping;
    protected SqlUpdate insertToken;
    protected SqlUpdate updateToken;
    protected SqlUpdate removeUserTokens;

    protected void initDao() {
        tokensBySeriesMapping = new TokensBySeriesMapping(getDataSource());
        insertToken = new InsertToken(getDataSource());
        updateToken = new UpdateToken(getDataSource());
        removeUserTokens = new RemoveUserTokens(getDataSource());

        if (createTableOnStartup) {
            getJdbcTemplate().execute(CREATE_TABLE_SQL);
        }
    }

    public void createNewToken(PersistentRememberMeToken token) {
        insertToken.update(
                new Object[] {token.getUsername(), token.getSeries(), token.getTokenValue(), token.getDate()});
    }

    public void updateToken(String series, String tokenValue, Date lastUsed) {
        updateToken.update(new Object[] {tokenValue, new Date(), series});
    }

    /**
     * Loads the token data for the supplied series identifier.
     *
     * If an error occurs, it will be reported and null will be returned (since the result should just be a failed
     * persistent login).
     *
     * @param seriesId
     * @return the token matching the series, or null if no match found or an exception occurred.
     */
    public PersistentRememberMeToken getTokenForSeries(String seriesId) {
        try {
            return (PersistentRememberMeToken) tokensBySeriesMapping.findObject(seriesId);
        } catch(IncorrectResultSizeDataAccessException moreThanOne) {
            logger.error("Querying token for series '" + seriesId + "' returned more than one value. Series" +
                    "should be unique");
        } catch(DataAccessException e) {
            logger.error("Failed to load token for series " + seriesId, e);
        }

        return null;
    }

    public void removeUserTokens(String username) {
        removeUserTokens.update(username);
    }

    /**
     * Intended for convenience in debugging. Will create the persistent_tokens database table when the class
     * is initialized during the initDao method.
     *
     * @param createTableOnStartup set to true to execute the
     */
    public void setCreateTableOnStartup(boolean createTableOnStartup) {
        this.createTableOnStartup = createTableOnStartup;
    }

    //~ Inner Classes ==================================================================================================

    protected class TokensBySeriesMapping extends MappingSqlQuery {
        protected TokensBySeriesMapping(DataSource ds) {
            super(ds, tokensBySeriesSql);
            declareParameter(new SqlParameter(Types.VARCHAR));
            compile();
        }

        protected Object mapRow(ResultSet rs, int rowNum) throws SQLException {
            PersistentRememberMeToken token =
                    new PersistentRememberMeToken(rs.getString(1), rs.getString(2), rs.getString(3), rs.getTimestamp(4));

            return token;
        }
    }

    protected class UpdateToken extends SqlUpdate {

        public UpdateToken(DataSource ds) {
            super(ds, updateTokenSql);
            setMaxRowsAffected(1);
            declareParameter(new SqlParameter(Types.VARCHAR));
            declareParameter(new SqlParameter(Types.TIMESTAMP));
            declareParameter(new SqlParameter(Types.VARCHAR));
            compile();
        }
    }

    protected class InsertToken extends SqlUpdate {

        public InsertToken(DataSource ds) {
            super(ds, insertTokenSql);
            declareParameter(new SqlParameter(Types.VARCHAR));
            declareParameter(new SqlParameter(Types.VARCHAR));
            declareParameter(new SqlParameter(Types.VARCHAR));
            declareParameter(new SqlParameter(Types.TIMESTAMP));
            compile();
        }
    }

    protected class RemoveUserTokens extends SqlUpdate {
        public RemoveUserTokens(DataSource ds) {
            super(ds, removeUserTokensSql);
            declareParameter(new SqlParameter(Types.VARCHAR));
            compile();
        }
    }
}
