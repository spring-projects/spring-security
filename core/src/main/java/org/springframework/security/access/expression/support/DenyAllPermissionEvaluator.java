package org.springframework.security.access.expression.support;

import java.io.Serializable;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.Authentication;
import org.springframework.security.access.expression.PermissionEvaluator;

/**
 * A null PermissionEvaluator which denies all access. Used by default for situations when permission
 * evaluation should not be required.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
class DenyAllPermissionEvaluator implements PermissionEvaluator {

    private final Log logger = LogFactory.getLog(getClass());

    /**
     * @return false always
     */
    public boolean hasPermission(Authentication authentication, Object target, Object permission) {
        logger.warn("Denying user " + authentication.getName() + " permission '" + permission + "' on object " + target);
        return false;
    }

    /**
     * @return false always
     */
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType,
                    Object permission) {
        logger.warn("Denying user " + authentication.getName() + " permission '" + permission + "' on object with Id '"
                        + targetId);
        return false;
    }

}
