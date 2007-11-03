package org.springframework.security.ui.rememberme;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public interface PersistentTokenRepository {

    void saveToken(PersistentRememberMeToken token);

    PersistentRememberMeToken getTokenForSeries(String seriesId);

    void removeAllTokens(String username);

}
