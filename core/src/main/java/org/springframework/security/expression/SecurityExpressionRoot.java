package org.springframework.security.expression;

import java.util.Set;

import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationTrustResolver;
import org.springframework.security.AuthenticationTrustResolverImpl;
import org.springframework.security.util.AuthorityUtils;

public class SecurityExpressionRoot {
    private Authentication authentication;
    private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
    private Object filterObject;
    private Object returnObject;

    /** Allows "permitAll" expression */
    public final boolean permitAll = true;

    /** Allows "denyAll" expression */
    public final boolean denyAll = false;


    public SecurityExpressionRoot(Authentication a) {
        this.authentication = a;
    }

    public final boolean hasRole(String role) {
        return hasAnyRole(role);
    }

    public boolean hasAnyRole(String... roles) {
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

    public Authentication getAuthentication() {
        return authentication;
    }

    public final boolean isFullyAuthenticated() {
        return !trustResolver.isAnonymous(authentication) && !trustResolver.isRememberMe(authentication);
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
}
