package org.springframework.security.ui.preauth;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.ui.WebAuthenticationDetails;
import org.springframework.security.GrantedAuthoritiesContainerImpl;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.MutableGrantedAuthoritiesContainer;

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

	private MutableGrantedAuthoritiesContainer authoritiesContainer = new GrantedAuthoritiesContainerImpl();

	public PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails(HttpServletRequest request) {
		super(request);
	}

	public GrantedAuthority[] getGrantedAuthorities() {
		return authoritiesContainer.getGrantedAuthorities();
	}

	public void setGrantedAuthorities(GrantedAuthority[] authorities) {
		this.authoritiesContainer.setGrantedAuthorities(authorities);
	}
	
    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append(super.toString() + "; ");
        sb.append(authoritiesContainer);
        return sb.toString();
    }	
}
