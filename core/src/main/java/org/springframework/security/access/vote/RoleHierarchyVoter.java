package org.springframework.security.access.vote;

import java.util.Collection;

import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
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
    Collection<? extends GrantedAuthority> extractAuthorities(Authentication authentication) {
        return roleHierarchy.getReachableGrantedAuthorities(authentication.getAuthorities());
    }
}
