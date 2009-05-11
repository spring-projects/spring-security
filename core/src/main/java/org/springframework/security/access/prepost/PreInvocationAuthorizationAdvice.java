package org.springframework.security.access.prepost;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.core.Authentication;

/**
 * Performs argument filtering and authorization logic before a method is invoked.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public interface PreInvocationAuthorizationAdvice {

    boolean before(Authentication authentication, MethodInvocation mi, PreInvocationAttribute preInvocationAttribute);
}
