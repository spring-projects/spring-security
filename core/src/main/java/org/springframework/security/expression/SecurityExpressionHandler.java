package org.springframework.security.expression;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.Authentication;

/**
 * Facade which isolates Spring Security's requirements from the implementation of the underlying
 * expression objects.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
public interface SecurityExpressionHandler {

    /**
     * Provides a evaluation context in which to evaluate security expressions for a method invocation.
     */
    EvaluationContext createEvaluationContext(Authentication auth, MethodInvocation mi);

    /**
     * Filters a target collection or array.
     *
     * @param filterTarget the array or collection to be filtered.
     * @param filterExpression the expression which should be used as the filter condition. If it returns false on
     *          evaluation, the object will be removed from the returned collection
     * @param ctx the current evaluation context (usualy as created through a call to
     *          {@link #createEvaluationContext(Authentication, MethodInvocation)}
     * @return the filtered collection or array
     */
    Object doFilter(Object filterTarget, Expression filterExpression, EvaluationContext ctx);

    /**
     * Used to inform the expression system of the return object
     *
     * @param returnObject the return object value
     * @param ctx the context within which the object should be set
     */
    void setReturnObject(Object returnObject, EvaluationContext ctx);

}
