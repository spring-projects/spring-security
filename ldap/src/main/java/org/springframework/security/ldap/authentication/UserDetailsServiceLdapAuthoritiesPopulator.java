package org.springframework.security.ldap.authentication;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.util.Assert;

/**
 * Simple LdapAuthoritiesPopulator which delegates to a UserDetailsService, using the name which
 * was supplied at login as the username.
 *
 *
 * @author Luke Taylor
 * @since 2.0
 */
public class UserDetailsServiceLdapAuthoritiesPopulator implements LdapAuthoritiesPopulator {
    private final UserDetailsService userDetailsService;

    public UserDetailsServiceLdapAuthoritiesPopulator(UserDetailsService userService) {
        Assert.notNull(userService, "userDetailsService cannot be null");
        this.userDetailsService = userService;
    }

    public Collection<GrantedAuthority> getGrantedAuthorities(DirContextOperations userData, String username) {
        return userDetailsService.loadUserByUsername(username).getAuthorities();
    }
}
