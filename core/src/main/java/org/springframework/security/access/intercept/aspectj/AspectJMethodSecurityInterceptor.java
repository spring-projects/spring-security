package org.springframework.security.access.intercept.aspectj;

import org.aspectj.lang.JoinPoint;
import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.access.intercept.aopalliance.MethodSecurityInterceptor;

/**
 * AspectJ {@code JoinPoint} security interceptor which wraps the {@code JoinPoint} in a {@code MethodInvocation}
 * adapter to make it compatible with security infrastructure classes which only support {@code MethodInvocation}s.
 * <p>
 * One of the {@code invoke} methods should be called from the {@code around()} advice in your aspect.
 * Alternatively you can use one of the pre-defined aspects from the aspects module.
 *
 * @author Luke Taylor
 * @since 3.0.3
 */
public final class AspectJMethodSecurityInterceptor extends MethodSecurityInterceptor {

    /**
     * Method that is suitable for user with @Aspect notation.
     *
     * @param jp The AspectJ joint point being invoked which requires a security decision
     * @return The returned value from the method invocation
     * @throws Throwable if the invocation throws one
     */
    public Object invoke(JoinPoint jp) throws Throwable {
        return super.invoke(new MethodInvocationAdapter(jp));
    }

    /**
     * Method that is suitable for user with traditional AspectJ-code aspects.
     *
     * @param jp The AspectJ joint point being invoked which requires a security decision
     * @param advisorProceed the advice-defined anonymous class that implements {@code AspectJCallback} containing
     *        a simple {@code return proceed();} statement
     *
     * @return The returned value from the method invocation
     */
    public Object invoke(JoinPoint jp, AspectJCallback advisorProceed) {
        Object result = null;
        InterceptorStatusToken token = super.beforeInvocation(new MethodInvocationAdapter(jp));

        try {
            result = advisorProceed.proceedWithObject();
        } finally {
            result = super.afterInvocation(token, result);
        }

        return result;
    }
}
