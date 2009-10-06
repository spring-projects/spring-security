package org.springframework.security.config;

import java.util.Collection;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.AfterInvocationProvider;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;

public class MockAfterInvocationProvider implements AfterInvocationProvider {

    public Object decide(Authentication authentication, Object object, Collection<ConfigAttribute> config, Object returnedObject)
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
