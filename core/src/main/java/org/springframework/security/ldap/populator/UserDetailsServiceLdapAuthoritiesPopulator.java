package org.springframework.security.ldap.populator;

import org.springframework.security.ldap.LdapAuthoritiesPopulator;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.ldap.core.DirContextOperations;

/**
 * Simple LdapAuthoritiesPopulator which delegates to a UserDetailsService, using the name which
 * was supplied at login as the username.
 *
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
public class UserDetailsServiceLdapAuthoritiesPopulator implements LdapAuthoritiesPopulator {
    private UserDetailsService userService;

    public UserDetailsServiceLdapAuthoritiesPopulator(UserDetailsService userService) {
        this.userService = userService;
    }

    public GrantedAuthority[] getGrantedAuthorities(DirContextOperations userData, String username) {
        return userService.loadUserByUsername(username).getAuthorities();
    }
}
