package org.springframework.security.providers.preauth;

import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.User;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.AuthenticationException;

import org.springframework.util.Assert;

/**
 * <p>
 * This PreAuthenticatedUserDetailsService implementation creates a UserDetails
 * object based solely on the information contained in the given
 * PreAuthenticatedAuthenticationToken. The user name is set to the name as
 * returned by PreAuthenticatedAuthenticationToken.getName(), the password is
 * set to a fixed dummy value (it will not be used by the
 * PreAuthenticatedAuthenticationProvider anyway), and the Granted Authorities
 * are retrieved from the details object as returned by
 * PreAuthenticatedAuthenticationToken.getDetails().
 * </p>
 * 
 * <p>
 * The details object as returned by
 * PreAuthenticatedAuthenticationToken.getDetails() must implement the
 * PreAuthenticatedGrantedAuthoritiesRetriever interface for this implementation
 * to work.
 * </p>
 */
public class PreAuthenticatedGrantedAuthoritiesUserDetailsService implements PreAuthenticatedUserDetailsService {
	/**
	 * Get a UserDetails object based on the user name contained in the given
	 * token, and the GrantedAuthorities as returned by the
	 * PreAuthenticatedGrantedAuthoritiesRetriever implementation as returned by
	 * the token.getDetails() method.
	 */
	public UserDetails getUserDetails(PreAuthenticatedAuthenticationToken token) throws AuthenticationException {
		Assert.notNull(token.getDetails());
		Assert.isInstanceOf(PreAuthenticatedGrantedAuthoritiesRetriever.class, token.getDetails());
		GrantedAuthority[] preAuthenticatedGrantedAuthorities = ((PreAuthenticatedGrantedAuthoritiesRetriever) token.getDetails())
				.getPreAuthenticatedGrantedAuthorities();
		UserDetails ud = new User(token.getName(), "N/A", true, true, true, true, preAuthenticatedGrantedAuthorities);
		return ud;
	}
}
