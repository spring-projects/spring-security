package org.springframework.security.ldap.authentication;

import java.util.Collection;

import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;

/**
 *
 * @author Luke Taylor
 * @since 3.0
 */
public final class NullLdapAuthoritiesPopulator implements LdapAuthoritiesPopulator {
    public Collection<GrantedAuthority> getGrantedAuthorities(DirContextOperations userDetails, String username) {
        return AuthorityUtils.NO_AUTHORITIES;
    }
}
