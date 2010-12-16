package org.springframework.security.access.hierarchicalroles;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;

import java.util.*;

/**
 * @author Luke Taylor
 */
public class RoleHierarchyAuthoritiesMapper implements GrantedAuthoritiesMapper {
    private final RoleHierarchy roleHierarchy;

    public RoleHierarchyAuthoritiesMapper(RoleHierarchy roleHierarchy) {
        this.roleHierarchy = roleHierarchy;
    }

    public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
        return roleHierarchy.getReachableGrantedAuthorities(authorities);
    }
}
