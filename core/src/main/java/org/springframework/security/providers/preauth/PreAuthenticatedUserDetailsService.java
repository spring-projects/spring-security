package org.springframework.security.providers.preauth;

import org.springframework.security.userdetails.UsernameNotFoundException;
import org.springframework.security.userdetails.UserDetails;


/**
 * Interface that allows for retrieving a UserDetails object based on a
 * PreAuthenticatedAuthenticationToken object.
 *
 * @author Ruud Senden
 * @since 2.0
 */
public interface PreAuthenticatedUserDetailsService {

	/**
	 *
	 * @param aPreAuthenticatedAuthenticationToken
	 *            The pre-authenticated authentication token
	 * @return UserDetails for the given authentication token.
	 * @throws UsernameNotFoundException
	 *             if no user details can be found for the given authentication
	 *             token
	 */
	UserDetails getUserDetails(PreAuthenticatedAuthenticationToken aPreAuthenticatedAuthenticationToken)
			throws UsernameNotFoundException;
}
