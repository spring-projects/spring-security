package org.springframework.security.access.prepost;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.security.core.Authentication;

/**
 * Performs argument filtering and authorization logic before a method is invoked.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public interface PreInvocationAuthorizationAdvice extends AopInfrastructureBean {

    /**
     * The "before" advice which should be executed to perform any filtering necessary and to decide whether
     * the method call is authorised.
     *
     * @param authentication the information on the principal on whose account the decision should be made
     * @param mi the method invocation being attempted
     * @param preInvocationAttribute the attribute built from the @PreFilter and @PostFilter annotations.
     * @return true if authorised, false otherwise
     */
    boolean before(Authentication authentication, MethodInvocation mi, PreInvocationAttribute preInvocationAttribute);
}
