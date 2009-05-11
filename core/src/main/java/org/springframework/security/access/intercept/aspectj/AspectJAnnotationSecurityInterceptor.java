package org.springframework.security.access.intercept.aspectj;

import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.access.intercept.AbstractSecurityInterceptor;
import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.access.method.MethodSecurityMetadataSource;

import org.aspectj.lang.JoinPoint;

/**
 * AspectJ interceptor that supports @Aspect notation.
 *
 * @author Mike Wiesner
 * @version $Id$
 */
public class AspectJAnnotationSecurityInterceptor extends AbstractSecurityInterceptor {
    //~ Instance fields ================================================================================================

    private MethodSecurityMetadataSource securityMetadataSource;

    //~ Methods ========================================================================================================

    public MethodSecurityMetadataSource getSecurityMetadataSource() {
        return this.securityMetadataSource;
    }

    public Class<? extends Object> getSecureObjectClass() {
        return JoinPoint.class;
    }

    /**
     * This method should be used to enforce security on a <code>JoinPoint</code>.
     *
     * @param jp The AspectJ joint point being invoked which requires a security decision
     * @param advisorProceed the advice-defined anonymous class that implements <code>AspectJCallback</code> containing
     *        a simple <code>return proceed();</code> statement
     *
     * @return The returned value from the method invocation
     */
    public Object invoke(JoinPoint jp, AspectJAnnotationCallback advisorProceed) throws Throwable {
        Object result = null;
        InterceptorStatusToken token = super.beforeInvocation(jp);

        try {
            result = advisorProceed.proceedWithObject();
        } finally {
            result = super.afterInvocation(token, result);
        }

        return result;
    }

    public SecurityMetadataSource obtainSecurityMetadataSource() {
        return this.securityMetadataSource;
    }

    public void setSecurityMetadataSource(MethodSecurityMetadataSource newSource) {
        this.securityMetadataSource = newSource;
    }

}
