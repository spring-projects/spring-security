package org.springframework.security.ldap;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.ldap.userdetails.LdapUserDetails;
import org.springframework.ldap.core.AuthenticationSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * An AuthenticationSource to retrieve authentication information stored in Spring Security's
 * {@link SecurityContextHolder}.
 * <p>
 * This is a copy of Spring LDAP's AcegiAuthenticationSource, updated for use with Spring Security 2.0.
 *
 * @author Mattias Arthursson
 * @author Luke Taylor
 * @since 2.0
 * @version $Id$
 */
public class SpringSecurityAuthenticationSource implements AuthenticationSource {
    private static final Log log = LogFactory.getLog(SpringSecurityAuthenticationSource.class);

    /**
     * Get the principals of the logged in user, in this case the distinguished
     * name.
     *
     * @return the distinguished name of the logged in user.
     */
    public String getPrincipal() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null) {
            log.warn("No Authentication object set in SecurityContext - returning empty String as Principal");
            return "";
        }

        Object principal = authentication.getPrincipal();

        if (principal instanceof LdapUserDetails) {
            LdapUserDetails details = (LdapUserDetails) principal;
            return details.getDn();
        } else if (authentication instanceof AnonymousAuthenticationToken) {
            if (log.isDebugEnabled()) {
                log.debug("Anonymous Authentication, returning empty String as Principal");
            }
            return "";
        } else {
            throw new IllegalArgumentException("The principal property of the authentication object"
                            + "needs to be an LdapUserDetails.");
        }
    }

    /**
     * @see org.springframework.ldap.core.AuthenticationSource#getCredentials()
     */
    public String getCredentials() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null) {
            log.warn("No Authentication object set in SecurityContext - returning empty String as Credentials");
            return "";
        }

        return (String) authentication.getCredentials();        
    }
}
