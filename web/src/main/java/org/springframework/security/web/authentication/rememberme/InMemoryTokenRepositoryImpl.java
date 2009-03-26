package org.springframework.security.web.authentication.rememberme;

import org.springframework.dao.DataIntegrityViolationException;

import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Simple <tt>PersistentTokenRepository</tt> implementation backed by a Map. Intended for testing only.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class InMemoryTokenRepositoryImpl implements PersistentTokenRepository {
    private Map<String, PersistentRememberMeToken> seriesTokens = new HashMap<String, PersistentRememberMeToken>();

    public synchronized void createNewToken(PersistentRememberMeToken token) {
        PersistentRememberMeToken current = seriesTokens.get(token.getSeries());

        if (current != null) {
            throw new DataIntegrityViolationException("Series Id '"+ token.getSeries() +"' already exists!");
        }

        seriesTokens.put(token.getSeries(), token);
    }

    public synchronized void updateToken(String series, String tokenValue, Date lastUsed) {
        PersistentRememberMeToken token = getTokenForSeries(series);

        PersistentRememberMeToken newToken = new PersistentRememberMeToken(token.getUsername(), series, tokenValue,
                new Date());

        // Store it, overwriting the existing one.
        seriesTokens.put(series, newToken);
    }

    public synchronized PersistentRememberMeToken getTokenForSeries(String seriesId) {
        return (PersistentRememberMeToken) seriesTokens.get(seriesId);
    }

    public synchronized void removeUserTokens(String username) {
        Iterator<String> series = seriesTokens.keySet().iterator();

        while (series.hasNext()) {
            Object seriesId = series.next();

            PersistentRememberMeToken token = (PersistentRememberMeToken) seriesTokens.get(seriesId);

            if (username.equals(token.getUsername())) {
                series.remove();
            }
        }
    }
}
