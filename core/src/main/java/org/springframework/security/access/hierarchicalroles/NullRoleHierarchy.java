package org.springframework.security.access.hierarchicalroles;

import java.util.List;

import org.springframework.security.core.GrantedAuthority;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public final class NullRoleHierarchy implements RoleHierarchy {

    public List<GrantedAuthority> getReachableGrantedAuthorities(List<GrantedAuthority> authorities) {
        return authorities;
    }

}
