package org.springframework.security.providers.preauth;

import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.security.userdetails.UsernameNotFoundException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.dao.DataAccessException;
import org.springframework.util.Assert;

/**
 * This implementation for PreAuthenticatedUserDetailsService wraps a regular
 * Acegi UserDetailsService implementation, to retrieve a UserDetails object
 * based on the user name contained in a PreAuthenticatedAuthenticationToken.
 */
public class UserDetailsByNameServiceWrapper implements PreAuthenticatedUserDetailsService, InitializingBean {
	private UserDetailsService userDetailsService = null;

	/**
	 * Check whether all required properties have been set.
	 * 
	 * @see org.springframework.beans.factory.InitializingBean#afterPropertiesSet()
	 */
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(userDetailsService, "UserDetailsService must be set");
	}

	/**
	 * Get the UserDetails object from the wrapped UserDetailsService
	 * implementation
	 */
	public UserDetails getUserDetails(PreAuthenticatedAuthenticationToken aJ2eeAuthenticationToken) throws UsernameNotFoundException,
			DataAccessException {
		return userDetailsService.loadUserByUsername(aJ2eeAuthenticationToken.getName());
	}

	/**
	 * Set the wrapped UserDetailsService implementation
	 * 
	 * @param aUserDetailsService
	 *            The wrapped UserDetailsService to set
	 */
	public void setUserDetailsService(UserDetailsService aUserDetailsService) {
		userDetailsService = aUserDetailsService;
	}
}
