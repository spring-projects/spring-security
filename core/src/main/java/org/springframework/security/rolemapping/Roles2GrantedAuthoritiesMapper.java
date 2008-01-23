package org.springframework.security.rolemapping;

import org.springframework.security.GrantedAuthority;

/**
 * Interface to be implemented by classes that can map a list of roles to a list
 * of Acegi GrantedAuthorities.
 *
 * @author Ruud Senden
 * @since 2.0
 */
public interface Roles2GrantedAuthoritiesMapper {
    /**
     * Implementations of this method should map the given list of roles to a
     * list of Acegi GrantedAuthorities. There are no restrictions for the
     * mapping process; a single role can be mapped to multiple Acegi
     * GrantedAuthorities, all roles can be mapped to a single Acegi
     * GrantedAuthority, some roles may not be mapped, etc.
     *
     * @param roles the roles to be mapped
     * @return the list of mapped GrantedAuthorities
     */
    public GrantedAuthority[] getGrantedAuthorities(String[] roles);
}
