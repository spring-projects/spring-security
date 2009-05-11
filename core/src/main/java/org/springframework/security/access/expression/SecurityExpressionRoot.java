package org.springframework.security.access.expression;

import java.util.Set;

import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;


/**
 * Base root object for use in Spring Security expression evaluations.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public abstract class SecurityExpressionRoot {
    protected final Authentication authentication;
    private AuthenticationTrustResolver trustResolver;
    /** Allows "permitAll" expression */
    public final boolean permitAll = true;

    /** Allows "denyAll" expression */
    public final boolean denyAll = false;

    public SecurityExpressionRoot(Authentication a) {
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
        Set<String> roleSet = AuthorityUtils.authorityListToSet(authentication.getAuthorities());

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

    public Object getPrincipal() {
        return authentication.getPrincipal();
    }

    public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
        this.trustResolver = trustResolver;
    }
}
