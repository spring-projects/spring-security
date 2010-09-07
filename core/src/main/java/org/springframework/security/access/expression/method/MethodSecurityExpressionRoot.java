package org.springframework.security.access.expression.method;

import java.io.Serializable;

import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.core.Authentication;


/**
 * Extended expression root object which contains extra method-specific functionality.
 *
 * @author Luke Taylor
 * @since 3.0
 */
class MethodSecurityExpressionRoot extends SecurityExpressionRoot {
    private Object filterObject;
    private Object returnObject;

    MethodSecurityExpressionRoot(Authentication a) {
        super(a);
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
