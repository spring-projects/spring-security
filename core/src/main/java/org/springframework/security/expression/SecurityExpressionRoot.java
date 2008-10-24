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

    public SecurityExpressionRoot(Authentication a) {
        this.authentication = a;
    }

    public boolean hasRole(String role) {
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

    public boolean isAnonymous() {
        return trustResolver.isAnonymous(authentication);
    }

    public boolean isRememberMe() {
        return trustResolver.isRememberMe(authentication);
    }

    public String getName() {
        return authentication.getName();
    }

    public boolean isFullyAuthenticated() {
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
}
