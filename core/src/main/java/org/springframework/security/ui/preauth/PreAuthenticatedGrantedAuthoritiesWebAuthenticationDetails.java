package org.springframework.security.ui.preauth;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.providers.preauth.PreAuthenticatedGrantedAuthoritiesRetriever;
import org.springframework.security.providers.preauth.PreAuthenticatedGrantedAuthoritiesSetter;
import org.springframework.security.ui.WebAuthenticationDetails;
import org.springframework.security.GrantedAuthority;

import org.apache.commons.lang.StringUtils;
import org.springframework.util.Assert;

/**
 * This WebAuthenticationDetails implementation allows for storing a list of
 * pre-authenticated Granted Authorities.
 */
public class PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails extends WebAuthenticationDetails implements
		PreAuthenticatedGrantedAuthoritiesRetriever, PreAuthenticatedGrantedAuthoritiesSetter {
	public static final long serialVersionUID = 1L;

	private GrantedAuthority[] preAuthenticatedGrantedAuthorities = null;

	public PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails(HttpServletRequest request) {
		super(request);
	}

	/**
	 * @return The String representation of this object.
	 */
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append(super.toString() + "; ");
		sb.append("preAuthenticatedGrantedAuthorities: " + StringUtils.join(preAuthenticatedGrantedAuthorities, ", "));
		return sb.toString();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.springframework.security.providers.preauth.PreAuthenticatedGrantedAuthoritiesRetriever#getPreAuthenticatedGrantedAuthorities()
	 */
	public GrantedAuthority[] getPreAuthenticatedGrantedAuthorities() {
		Assert.notNull(preAuthenticatedGrantedAuthorities, "Pre-authenticated granted authorities have not been set");
		GrantedAuthority[] result = new GrantedAuthority[preAuthenticatedGrantedAuthorities.length];
		System.arraycopy(preAuthenticatedGrantedAuthorities, 0, result, 0, result.length);
		return result;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.springframework.security.providers.preauth.j2ee.PreAuthenticatedGrantedAuthoritiesSetter#setJ2eeBasedGrantedAuthorities()
	 */
	public void setPreAuthenticatedGrantedAuthorities(GrantedAuthority[] aJ2eeBasedGrantedAuthorities) {
		this.preAuthenticatedGrantedAuthorities = new GrantedAuthority[aJ2eeBasedGrantedAuthorities.length];
		System.arraycopy(aJ2eeBasedGrantedAuthorities, 0, preAuthenticatedGrantedAuthorities, 0, preAuthenticatedGrantedAuthorities.length);
	}
}
