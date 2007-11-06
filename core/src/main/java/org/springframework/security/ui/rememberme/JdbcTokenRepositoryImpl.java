package org.springframework.security.ui.rememberme;

import org.springframework.jdbc.core.support.JdbcDaoSupport;

/**
 * 
 * @author Luke Taylor
 * @version $Id$
 */
public class JdbcTokenRepositoryImpl extends JdbcDaoSupport implements PersistentTokenRepository {
    //~ Static fields/initializers =====================================================================================    
    public static final String DEF_TOKEN_BY_SERIES_QUERY =
            "select username,series,token from persistent_logins where series = ?";
    public static final String DEF_INSERT_TOKEN_STATEMENT =
            "insert into persistent_logins (username,series,token) values(?,?,?)";
    public static final String DEF_REMOVE_USER_TOKENS_STATEMENT =
            "delete from persistent_logins where username = ?";

    //~ Instance fields ================================================================================================

    private String tokensBySeriesQuery = DEF_TOKEN_BY_SERIES_QUERY;
    private String insertTokenStatement = DEF_INSERT_TOKEN_STATEMENT;
    private String removeUserTokensStatement = DEF_REMOVE_USER_TOKENS_STATEMENT;

    public void saveToken(PersistentRememberMeToken token) {
    }

    public PersistentRememberMeToken getTokenForSeries(String seriesId) {
        return null;
    }

    public void removeAllTokens(String username) {
    }
}
