package org.springframework.security.expression;

import org.springframework.security.Authentication;

/**
 * Strategy used in expression evaluation to determine whether a user has a permission or permissions
 * for a given domain object.
 *
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
public interface PermissionEvaluator {
    /**
     *
     * @param authentication represents the user in question. Should not be null.
     * @param targetDomainObject the domain object for which permissions should be checked. May be null
     *          in which case implementations should return false, as the null condition can be checked explicitly
     *          in the expression.
     * @param permission a representation of the permission object as supplied by the expression system. Not null.
     * @return true if the permission is granted, false otherwise
     */
    boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission);
}
