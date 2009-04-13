package org.springframework.security.userdetails;

import org.springframework.security.core.Authentication;


/**
 * Interface that allows for retrieving a UserDetails object based on an <tt>Authentication</tt> object.
 *
 * @author Ruud Senden
 * @version $Id$
 * @since 2.0
 */
public interface AuthenticationUserDetailsService {

    /**
     *
     * @param token The pre-authenticated authentication token
     * @return UserDetails for the given authentication token, never null.
     * @throws UsernameNotFoundException
     *             if no user details can be found for the given authentication
     *             token
     */
    UserDetails loadUserDetails(Authentication token) throws UsernameNotFoundException;
}
