package org.springframework.security.ui.rememberme;

import org.springframework.dao.DataIntegrityViolationException;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class InMemoryTokenRepositoryImpl implements PersistentTokenRepository {
    private Map seriesTokens = new HashMap();

    public synchronized void saveToken(PersistentRememberMeToken token) {
        PersistentRememberMeToken current = (PersistentRememberMeToken) seriesTokens.get(token.getSeries());

        if (current != null && !token.getUsername().equals(current.getUsername())) {
            throw new DataIntegrityViolationException("Series Id already exists with different username");
        }

        // Store it, overwriting the existing one.
        seriesTokens.put(token.getSeries(), token);
    }

    public synchronized PersistentRememberMeToken getTokenForSeries(String seriesId) {
        return (PersistentRememberMeToken) seriesTokens.get(seriesId);
    }

    public synchronized void removeAllTokens(String username) {
        Iterator series = seriesTokens.keySet().iterator();

        while (series.hasNext()) {
            Object seriesId = series.next();

            PersistentRememberMeToken token = (PersistentRememberMeToken) seriesTokens.get(seriesId);

            if (username.equals(token.getUsername())) {
                series.remove();
            }
        }
    }
}
