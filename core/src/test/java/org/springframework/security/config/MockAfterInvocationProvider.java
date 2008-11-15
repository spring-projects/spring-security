package org.springframework.security.config;

import java.util.List;

import org.springframework.security.AccessDeniedException;
import org.springframework.security.Authentication;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.afterinvocation.AfterInvocationProvider;

public class MockAfterInvocationProvider implements AfterInvocationProvider {

    public Object decide(Authentication authentication, Object object, List<ConfigAttribute> config, Object returnedObject)
            throws AccessDeniedException {
        return returnedObject;
    }

    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    public boolean supports(Class<?> clazz) {
        return true;
    }

}
