package org.springframework.security.providers.preauth;

import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.User;
import org.springframework.security.GrantedAuthoritiesContainer;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.AuthenticationException;
import org.springframework.security.Authentication;

import org.springframework.util.Assert;

/**
 * <p>
 * This AuthenticationUserDetailsService implementation creates a UserDetails
 * object based solely on the information contained in the given
 * PreAuthenticatedAuthenticationToken. The user name is set to the name as
 * returned by PreAuthenticatedAuthenticationToken.getName(), the password is
 * set to a fixed dummy value (it will not be used by the
 * PreAuthenticatedAuthenticationProvider anyway), and the Granted Authorities
 * are retrieved from the details object as returned by
 * PreAuthenticatedAuthenticationToken.getDetails().
 * 
 * <p>
 * The details object as returned by PreAuthenticatedAuthenticationToken.getDetails() must implement the
 * {@link GrantedAuthoritiesContainer} interface for this implementation to work.
 *
 * @author Ruud Senden
 * @since 2.0
 */
public class PreAuthenticatedGrantedAuthoritiesUserDetailsService implements AuthenticationUserDetailsService {
	/**
	 * Get a UserDetails object based on the user name contained in the given
	 * token, and the GrantedAuthorities as returned by the
	 * GrantedAuthoritiesContainer implementation as returned by
	 * the token.getDetails() method.
	 */
	public final UserDetails loadUserDetails(Authentication token) throws AuthenticationException {
		Assert.notNull(token.getDetails());
		Assert.isInstanceOf(GrantedAuthoritiesContainer.class, token.getDetails());
		GrantedAuthority[] authorities = ((GrantedAuthoritiesContainer) token.getDetails()).getGrantedAuthorities();
		UserDetails ud = createuserDetails(token, authorities);
		return ud;
	}
	
	/**
	 * Creates the final <tt>UserDetails</tt> object. Can be overridden to customize the contents.
	 * 
	 * @param token the authentication request token
	 * @param authorities the pre-authenticated authorities.
	 */
	protected UserDetails createuserDetails(Authentication token, GrantedAuthority[] authorities) {
		return new User(token.getName(), "N/A", true, true, true, true, authorities);
	}
}
