package org.springframework.security.access.expression;

import org.springframework.security.core.Authentication;

/**
 * Standard interface for expression root objects used with expression-based
 * security.
 *
 * @author Andrei Stefan
 * @author Luke Taylor
 * @since 3.1.1
 */
public interface SecurityExpressionOperations {

    Authentication getAuthentication();

    boolean hasAuthority(String authority);

    boolean hasAnyAuthority(String... authorities);

    boolean hasRole(String role);

    boolean hasAnyRole(String... roles);

    boolean permitAll();

    boolean denyAll();

    boolean isAnonymous();

    boolean isAuthenticated();

    boolean isRememberMe();

    boolean isFullyAuthenticated();

    boolean hasPermission(Object target, Object permission);

    boolean hasPermission(Object targetId, String targetType, Object permission);

}
