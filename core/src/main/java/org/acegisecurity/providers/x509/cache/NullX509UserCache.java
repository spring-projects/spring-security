package net.sf.acegisecurity.providers.x509.cache;

import net.sf.acegisecurity.UserDetails;
import net.sf.acegisecurity.providers.x509.X509UserCache;

import java.security.cert.X509Certificate;

/**
 * "Cache" that doesn't do any caching.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class NullX509UserCache implements X509UserCache {
    //~ Methods ================================================================

    public UserDetails getUserFromCache(X509Certificate certificate) {
        return null;
    }

    public void putUserInCache(X509Certificate certificate, UserDetails user) {}

    public void removeUserFromCache(X509Certificate certificate) {}
}
