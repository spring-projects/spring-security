package org.springframework.security.userdetails;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public interface UserDetailsCache {

    boolean userIsCached(String username);

    void removeUserFromCache(String username);

    void clearCache();    
}
