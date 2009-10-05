package org.springframework.security.access.hierarchicalroles;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public final class NullRoleHierarchy implements RoleHierarchy {

    public Collection<GrantedAuthority> getReachableGrantedAuthorities(Collection<GrantedAuthority> authorities) {
        return authorities;
    }

}
