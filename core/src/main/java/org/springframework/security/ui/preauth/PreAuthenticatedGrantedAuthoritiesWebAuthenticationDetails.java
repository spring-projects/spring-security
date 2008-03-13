package org.springframework.security.ui.preauth;

import java.util.Arrays;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.ui.WebAuthenticationDetails;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.MutableGrantedAuthoritiesContainer;

import org.springframework.util.Assert;

/**
 * This WebAuthenticationDetails implementation allows for storing a list of
 * pre-authenticated Granted Authorities.
 *
 * @author Ruud Senden
 * @author Luke Taylor
 * @since 2.0
 */
public class PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails extends WebAuthenticationDetails implements
		MutableGrantedAuthoritiesContainer {
	public static final long serialVersionUID = 1L;

	private GrantedAuthority[] preAuthenticatedGrantedAuthorities = null;

	public PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails(HttpServletRequest request) {
		super(request);
	}

	public GrantedAuthority[] getGrantedAuthorities() {
		Assert.notNull(preAuthenticatedGrantedAuthorities, "Pre-authenticated granted authorities have not been set");
		GrantedAuthority[] result = new GrantedAuthority[preAuthenticatedGrantedAuthorities.length];
		System.arraycopy(preAuthenticatedGrantedAuthorities, 0, result, 0, result.length);
		return result;
	}

	public void setGrantedAuthorities(GrantedAuthority[] authorities) {
		this.preAuthenticatedGrantedAuthorities = new GrantedAuthority[authorities.length];
		System.arraycopy(authorities, 0, preAuthenticatedGrantedAuthorities, 0, preAuthenticatedGrantedAuthorities.length);
	}
	
    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append(super.toString() + "; ");
        sb.append("preAuthenticatedGrantedAuthorities: " + Arrays.asList(preAuthenticatedGrantedAuthorities));
        return sb.toString();
    }	
}
