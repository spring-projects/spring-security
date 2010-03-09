package org.springframework.security.access.intercept.aspectj.aspect;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.*;
import org.springframework.security.access.intercept.aspectj.AspectJCallback;
import org.springframework.security.access.intercept.aspectj.AspectJMethodSecurityInterceptor;

/**
 * Concrete AspectJ aspect using Spring Security @Secured annotation
 * for JDK 1.5+.
 *
 * <p>
 * When using this aspect, you <i>must</i> annotate the implementation class
 * (and/or methods within that class), <i>not</i> the interface (if any) that
 * the class implements. AspectJ follows Java's rule that annotations on
 * interfaces are <i>not</i> inherited. This will vary from Spring AOP.
 *
 * @author Mike Wiesner
 * @author Luke Taylor
 * @since 3.1
 */
public aspect AnnotationSecurityAspect implements InitializingBean {

    /**
     * Matches the execution of any public method in a type with the Secured
     * annotation, or any subtype of a type with the Secured annotation.
     */
    private pointcut executionOfAnyPublicMethodInAtSecuredType() :
        execution(public * ((@Secured *)+).*(..)) && @this(Secured);

    /**
     * Matches the execution of any method with the Secured annotation.
     */
    private pointcut executionOfSecuredMethod() :
        execution(* *(..)) && @annotation(Secured);

    /**
     * Matches the execution of any method with Pre/Post annotations.
     */
    private pointcut executionOfPrePostAnnotatedMethod() :
        execution(* *(..)) && (@annotation(PreAuthorize) || @annotation(PreFilter)
                || @annotation(PostAuthorize) || @annotation(PostFilter));

    private pointcut securedMethodExecution() :
        executionOfAnyPublicMethodInAtSecuredType() ||
        executionOfSecuredMethod() ||
        executionOfPrePostAnnotatedMethod();

    private AspectJMethodSecurityInterceptor securityInterceptor;

    Object around(): securedMethodExecution() {
        if (this.securityInterceptor == null) {
            return proceed();
        }

        AspectJCallback callback = new AspectJCallback() {
            public Object proceedWithObject() {
                return proceed();
            }
        };

        return this.securityInterceptor.invoke(thisJoinPoint, callback);
    }

    public void setSecurityInterceptor(AspectJMethodSecurityInterceptor securityInterceptor) {
        this.securityInterceptor = securityInterceptor;
    }

    public void afterPropertiesSet() throws Exception {
        if (this.securityInterceptor == null) {
            throw new IllegalArgumentException("securityInterceptor required");
        }
    }

}
