package org.springframework.security.expression;

import org.springframework.security.Authentication;

/**
 * A null PermissionEvaluator which denies all access. Used by default for situations when permission
 * evaluation should not be required.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
public class DenyAllPermissionEvaluator implements PermissionEvaluator {

    /**
     * @return false always
     */
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        return false;
    }

}
