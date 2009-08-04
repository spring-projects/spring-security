package org.springframework.security.access.prepost;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;

/**
 * Performs filtering and authorization logic after a method is invoked.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public interface PostInvocationAuthorizationAdvice extends AopInfrastructureBean {

    Object after(Authentication authentication, MethodInvocation mi,
            PostInvocationAttribute pia, Object returnedObject) throws AccessDeniedException;
}
