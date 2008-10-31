package org.springframework.security.vote;

import java.util.List;

import org.springframework.security.Authentication;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.userdetails.hierarchicalroles.RoleHierarchy;
import org.springframework.util.Assert;

/**
 * Extended RoleVoter which uses a {@link RoleHierarchy} definition to determine the
 * roles allocated to the current user before voting.
 *
 * @author Luke Taylor
 * @since 2.0.4
 */
public class RoleHierarchyVoter extends RoleVoter {
    private RoleHierarchy roleHierarchy = null;

    public RoleHierarchyVoter(RoleHierarchy roleHierarchy) {
        Assert.notNull(roleHierarchy, "RoleHierarchy must not be null");
        this.roleHierarchy = roleHierarchy;
    }

    /**
     * Calls the <tt>RoleHierarchy</tt> to obtain the complete set of user authorities.
     */
    @Override
    List<GrantedAuthority> extractAuthorities(Authentication authentication) {
        return roleHierarchy.getReachableGrantedAuthorities(authentication.getAuthorities());
    }
}
