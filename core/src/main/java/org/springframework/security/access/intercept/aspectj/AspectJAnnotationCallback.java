package org.springframework.security.access.intercept.aspectj;


/**
 * Called by the {@link AspectJAnnotationSecurityInterceptor} when it wishes for the
 * AspectJ processing to continue.
 *
 * @author Mike Wiesner
 */

public interface AspectJAnnotationCallback {
    //~ Methods ========================================================================================================

    Object proceedWithObject() throws Throwable;
}
