package org.springframework.security.ui.preauth;

import java.util.Arrays;

import org.springframework.security.GrantedAuthority;
import org.springframework.security.MutableGrantedAuthoritiesContainer;
import org.springframework.security.ui.AuthenticationDetails;
import org.springframework.util.Assert;

/**
 * This AuthenticationDetails implementation allows for storing a list of
 * pre-authenticated Granted Authorities.
 * 
 * @author Ruud Senden
 * @since 2.0
 */
public class PreAuthenticatedGrantedAuthoritiesAuthenticationDetails extends AuthenticationDetails implements
		MutableGrantedAuthoritiesContainer {
	public static final long serialVersionUID = 1L;

	private GrantedAuthority[] preAuthenticatedGrantedAuthorities = null;

	public PreAuthenticatedGrantedAuthoritiesAuthenticationDetails(Object context) {
		super(context);
	}

	/**
	 * @return The String representation of this object.
	 */
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append(super.toString() + "; ");
		sb.append("preAuthenticatedGrantedAuthorities: " + Arrays.asList(preAuthenticatedGrantedAuthorities));
		return sb.toString();
	}

	/**
	 * 
	 * @see org.springframework.security.GrantedAuthoritiesContainer#getGrantedAuthorities()
	 */
	public GrantedAuthority[] getGrantedAuthorities() {
		Assert.notNull(preAuthenticatedGrantedAuthorities, "Pre-authenticated granted authorities have not been set");
		GrantedAuthority[] result = new GrantedAuthority[preAuthenticatedGrantedAuthorities.length];
		System.arraycopy(preAuthenticatedGrantedAuthorities, 0, result, 0, result.length);
		return result;
	}

	/**
	 * @see org.springframework.security.MutableGrantedAuthoritiesContainer#setGrantedAuthorities()
	 */
	public void setGrantedAuthorities(GrantedAuthority[] aJ2eeBasedGrantedAuthorities) {
		this.preAuthenticatedGrantedAuthorities = new GrantedAuthority[aJ2eeBasedGrantedAuthorities.length];
		System.arraycopy(aJ2eeBasedGrantedAuthorities, 0, preAuthenticatedGrantedAuthorities, 0, preAuthenticatedGrantedAuthorities.length);
	}
}
