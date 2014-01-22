package org.springframework.security.access.expression;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;


/**
 * Base root object for use in Spring Security expression evaluations.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public abstract class SecurityExpressionRoot implements SecurityExpressionOperations {
    protected final Authentication authentication;
    private AuthenticationTrustResolver trustResolver;
    private RoleHierarchy roleHierarchy;
    private Set<String> roles;

    /** Allows "permitAll" expression */
    public final boolean permitAll = true;

    /** Allows "denyAll" expression */
    public final boolean denyAll = false;
    private PermissionEvaluator permissionEvaluator;
    public final String read = "read";
    public final String write = "write";
    public final String create = "create";
    public final String delete = "delete";
    public final String admin = "administration";

    /**
     * Creates a new instance
     * @param authentication the {@link Authentication} to use. Cannot be null.
     */
    public SecurityExpressionRoot(Authentication authentication) {
        if (authentication == null) {
            throw new IllegalArgumentException("Authentication object cannot be null");
        }
        this.authentication = authentication;
    }

    public final boolean hasAuthority(String authority) {
        return hasRole(authority);
    }

    public final boolean hasAnyAuthority(String... authorities) {
        return hasAnyRole(authorities);
    }

    public final boolean hasRole(String role) {
        return getAuthoritySet().contains(role);
    }

    public final boolean hasAnyRole(String... roles) {
        Set<String> roleSet = getAuthoritySet();

        for (String role : roles) {
            if (roleSet.contains(role)) {
                return true;
            }
        }

        return false;
    }

    public final Authentication getAuthentication() {
        return authentication;
    }

    public final boolean permitAll() {
        return true;
    }

    public final boolean denyAll() {
        return false;
    }

    public final boolean isAnonymous() {
        return trustResolver.isAnonymous(authentication);
    }

    public final boolean isAuthenticated() {
        return !isAnonymous();
    }

    public final boolean isRememberMe() {
        return trustResolver.isRememberMe(authentication);
    }

    public final boolean isFullyAuthenticated() {
        return !trustResolver.isAnonymous(authentication) && !trustResolver.isRememberMe(authentication);
    }

    /**
     * Convenience method to access {@link Authentication#getPrincipal()} from {@link #getAuthentication()}
     * @return
     */
    public Object getPrincipal() {
        return authentication.getPrincipal();
    }

    public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
        this.trustResolver = trustResolver;
    }

    public void setRoleHierarchy(RoleHierarchy roleHierarchy) {
        this.roleHierarchy = roleHierarchy;
    }

    private Set<String> getAuthoritySet() {
        if (roles == null) {
            roles = new HashSet<String>();
            Collection<? extends GrantedAuthority> userAuthorities = authentication.getAuthorities();

            if (roleHierarchy != null) {
                userAuthorities = roleHierarchy.getReachableGrantedAuthorities(userAuthorities);
            }

            roles = AuthorityUtils.authorityListToSet(userAuthorities);
        }

        return roles;
    }


    public boolean hasPermission(Object target, Object permission) {
        return permissionEvaluator.hasPermission(authentication, target, permission);
    }

    public boolean hasPermission(Object targetId, String targetType, Object permission) {
        return permissionEvaluator.hasPermission(authentication, (Serializable)targetId, targetType, permission);
    }

    public void setPermissionEvaluator(PermissionEvaluator permissionEvaluator) {
        this.permissionEvaluator = permissionEvaluator;
    }
}
