package org.springframework.security.ui.rememberme;

import java.util.Date;

/**
 * The abstraction used by {@link PersistentTokenBasedRememberMeServices} to store the persistent
 * login tokens for a user.
 *
 * @see JdbcTokenRepositoryImpl
 * @see InMemoryTokenRepositoryImpl 
 *
 * @author Luke Taylor
 * @version $Id$
 */
public interface PersistentTokenRepository {

    void createNewToken(PersistentRememberMeToken token);

    void updateToken(String series, String tokenValue, Date lastUsed);

    PersistentRememberMeToken getTokenForSeries(String seriesId);

    void removeUserTokens(String username);

}
