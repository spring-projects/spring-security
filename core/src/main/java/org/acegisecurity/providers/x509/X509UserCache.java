package net.sf.acegisecurity.providers.x509;

import net.sf.acegisecurity.UserDetails;

import java.security.cert.X509Certificate;

/**
 * Provides a cache of {@link UserDetails} objects for the
 * {@link X509AuthenticationProvider}.
 * <p>
 * Similar in function to the {@link net.sf.acegisecurity.providers.dao.UserCache}
 * used by the Dao provider, but the cache is keyed with the user's certificate
 * rather than the user name.  
 * </p>
 *
 * @author Luke Taylor
 * @version $Id$
 */
public interface X509UserCache {

    UserDetails getUserFromCache(X509Certificate userCertificate);

    void putUserInCache(X509Certificate key, UserDetails user);

    void removeUserFromCache(X509Certificate key);
}
