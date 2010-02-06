package org.springframework.security.config.method;

import java.io.Serializable;

import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;

public class TestPermissionEvaluator implements PermissionEvaluator {

    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        return false;
    }

    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType,
            Object permission) {
        return false;
    }

}
