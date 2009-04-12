package org.springframework.security.access.intercept.method.aspectj;


/**
 * Called by the {@link AspectJAnnotationSecurityInterceptor} when it wishes for the
 * AspectJ processing to continue.
 *
 * @author Mike Wiesner
 * @version $Id$
 */

public interface AspectJAnnotationCallback {
    //~ Methods ========================================================================================================

    Object proceedWithObject() throws Throwable;
}
