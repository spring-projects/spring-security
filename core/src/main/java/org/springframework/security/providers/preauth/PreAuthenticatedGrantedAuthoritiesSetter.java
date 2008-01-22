package org.springframework.security.providers.preauth;

import org.springframework.security.GrantedAuthority;

/**
 * Counterpart of PreAuthenticatedGrantedAuthoritiesRetriever that allows
 * setting a list of pre-authenticated GrantedAuthorities. This interface is not
 * actually being used by the PreAuthenticatedAuthenticationProvider or one of
 * its related classes, but may be useful for classes that also implement
 * PreAuthenticatedGrantedAuthoritiesRetriever.
 */
public interface PreAuthenticatedGrantedAuthoritiesSetter {
	/**
	 * @param aPreAuthenticatedGrantedAuthorities
	 *            The pre-authenticated GrantedAuthority[] to set
	 */
	public void setPreAuthenticatedGrantedAuthorities(GrantedAuthority[] aPreAuthenticatedGrantedAuthorities);
}
