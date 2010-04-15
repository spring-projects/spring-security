package org.springframework.security.core.userdetails;

import org.springframework.security.core.Authentication;


/**
 * Interface that allows for retrieving a UserDetails object based on an <tt>Authentication</tt> object.
 *
 * @author Ruud Senden
 * @since 2.0
 */
public interface AuthenticationUserDetailsService<T extends Authentication> {

    /**
     *
     * @param token The pre-authenticated authentication token
     * @return UserDetails for the given authentication token, never null.
     * @throws UsernameNotFoundException
     *             if no user details can be found for the given authentication
     *             token
     */
    UserDetails loadUserDetails(T token) throws UsernameNotFoundException;
}
