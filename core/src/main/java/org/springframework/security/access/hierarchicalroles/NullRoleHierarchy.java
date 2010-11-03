package org.springframework.security.access.hierarchicalroles;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;

/**
 *
 * @author Luke Taylor
 * @since 3.0
 */
public final class NullRoleHierarchy implements RoleHierarchy {

    public Collection<? extends GrantedAuthority> getReachableGrantedAuthorities(Collection<? extends GrantedAuthority> authorities) {
        return authorities;
    }

}
