package org.springframework.security.expression.support;

import java.io.Serializable;

import org.springframework.security.Authentication;
import org.springframework.security.expression.PermissionEvaluator;

public class MethodInvocationSecurityExpressionRoot extends SecurityExpressionRoot {
    private PermissionEvaluator permissionEvaluator;
    private Object filterObject;
    private Object returnObject;
    public final String read = "read";
    public final String write = "write";
    public final String create = "create";
    public final String delete = "delete";
    public final String admin = "administration";

    MethodInvocationSecurityExpressionRoot(Authentication a) {
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
