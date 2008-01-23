package org.springframework.security.providers.preauth;

import org.springframework.security.GrantedAuthority;


/**
 * Interface that allows for retrieval of a list of pre-authenticated Granted
 * Authorities.
 *
 * @author Ruud Senden
 * @since 2.0
 */
public interface PreAuthenticatedGrantedAuthoritiesRetriever {
    /**
     * @return GrantedAuthority[] List of pre-authenticated GrantedAuthorities
     */
    GrantedAuthority[] getPreAuthenticatedGrantedAuthorities();
}
