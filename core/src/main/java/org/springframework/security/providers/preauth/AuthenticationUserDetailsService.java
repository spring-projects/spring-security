package org.springframework.security.providers.preauth;

import org.springframework.security.userdetails.UsernameNotFoundException;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.Authentication;


/**
 * Interface that allows for retrieving a UserDetails object based on a
 * PreAuthenticatedAuthenticationToken object.
 *
 * @author Ruud Senden
 * @version $Id$
 * @since 2.0
 */
public interface AuthenticationUserDetailsService {

	/**
	 *
	 * @param token The pre-authenticated authentication token
	 * @return UserDetails for the given authentication token.
	 * @throws UsernameNotFoundException
	 *             if no user details can be found for the given authentication
	 *             token
	 */
	UserDetails loadUserDetails(Authentication token) throws UsernameNotFoundException;
}
