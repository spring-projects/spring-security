package org.springframework.security.integration.python;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PostInvocationAttribute;
import org.springframework.security.access.prepost.PostInvocationAuthorizationAdvice;
import org.springframework.security.core.Authentication;

public class PythonInterpreterPostInvocationAdvice implements PostInvocationAuthorizationAdvice{

    public Object after(Authentication authentication, MethodInvocation mi, PostInvocationAttribute pia,
            Object returnedObject) throws AccessDeniedException {
        return returnedObject;
    }
}
