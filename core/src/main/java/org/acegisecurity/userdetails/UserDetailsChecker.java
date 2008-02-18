package org.acegisecurity.userdetails;

/**
 * @author Luke Taylor
 * @version $Id$
 * @since 1.0.7
 */
public interface UserDetailsChecker {
    void check(UserDetails toCheck);
}
