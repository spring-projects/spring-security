package org.springframework.security.expression;

import java.io.Serializable;
import java.util.Set;

import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationTrustResolver;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.util.AuthorityUtils;


/**
 * Default root object for use in Spring Security expression evaluations.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
public class SecurityExpressionRoot {
    private Authentication authentication;
    private AuthenticationTrustResolver trustResolver;
    private PermissionEvaluator permissionEvaluator;
    private Object filterObject;
    private Object returnObject;

    /** Allows "permitAll" expression */
    public final boolean permitAll = true;

    /** Allows "denyAll" expression */
    public final boolean denyAll = false;

    public final String read = "read";
    public final String write = "write";
    public final String create = "create";
    public final String delete = "delete";
    public final String admin = "admin";


    SecurityExpressionRoot(Authentication a) {
        if (a == null) {
            throw new IllegalArgumentException("Authentication object cannot be null");
        }
        this.authentication = a;
    }

    public final boolean hasRole(String role) {
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            if (role.equals(authority.getAuthority())) {
                return true;
            }
        }

        return false;
    }

    public final boolean hasAnyRole(String... roles) {
        Set roleSet = AuthorityUtils.authorityArrayToSet(authentication.getAuthorities());

        for (String role : roles) {
            if (roleSet.contains(role)) {
                return true;
            }
        }

        return false;
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

    public final boolean isRememberMe() {
        return trustResolver.isRememberMe(authentication);
    }

    public final boolean isFullyAuthenticated() {
        return !trustResolver.isAnonymous(authentication) && !trustResolver.isRememberMe(authentication);
    }

    public boolean hasPermission(Object target, Object permission) {
        return permissionEvaluator.hasPermission(authentication, target, permission);
    }

    public boolean hasPermission(Object targetId, String targetType, Object permission) {
        return permissionEvaluator.hasPermission(authentication, (Serializable)targetId, targetType, permission);
    }

    public Authentication getAuthentication() {
        return authentication;
    }

    public void setFilterObject(Object filterObject) {
        this.filterObject = filterObject;
    }

    public Object getFilterObject() {
        return filterObject;
    }

    public void setReturnObject(Object returnObject) {
        this.returnObject = returnObject;
    }

    public Object getReturnObject() {
        return returnObject;
    }

    public Object getPrincipal() {
        return authentication.getPrincipal();
    }

    public void setPermissionEvaluator(PermissionEvaluator permissionEvaluator) {
        this.permissionEvaluator = permissionEvaluator;
    }

    public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
        this.trustResolver = trustResolver;
    }


}
