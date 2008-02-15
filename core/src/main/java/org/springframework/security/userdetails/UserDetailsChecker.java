package org.springframework.security.userdetails;

/**
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
public interface UserDetailsChecker {
    void check(UserDetails toCheck);
}
