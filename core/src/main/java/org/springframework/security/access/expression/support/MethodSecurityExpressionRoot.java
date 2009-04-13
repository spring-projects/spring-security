package org.springframework.security.access.expression.support;

import java.io.Serializable;

import org.springframework.security.access.expression.PermissionEvaluator;
import org.springframework.security.core.Authentication;


/**
 * Extended expression root object which contains extra method-specific functionality.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
class MethodSecurityExpressionRoot extends SecurityExpressionRoot {
    private PermissionEvaluator permissionEvaluator;
    private Object filterObject;
    private Object returnObject;
    public final String read = "read";
    public final String write = "write";
    public final String create = "create";
    public final String delete = "delete";
    public final String admin = "administration";

    MethodSecurityExpressionRoot(Authentication a) {
        super(a);
    }

    public boolean hasPermission(Object target, Object permission) {
        return permissionEvaluator.hasPermission(authentication, target, permission);
    }

    public boolean hasPermission(Object targetId, String targetType, Object permission) {
        return permissionEvaluator.hasPermission(authentication, (Serializable)targetId, targetType, permission);
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

    public void setPermissionEvaluator(PermissionEvaluator permissionEvaluator) {
        this.permissionEvaluator = permissionEvaluator;
    }

}
