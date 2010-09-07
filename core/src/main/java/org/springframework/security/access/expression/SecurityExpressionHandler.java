package org.springframework.security.access.expression;

import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.security.core.Authentication;

/**
 * Facade which isolates Spring Security's requirements for evaluating security expressions
 * from the implementation of the underlying expression objects
 *
 * @author Luke Taylor
 * @since 3.1
 */
public interface SecurityExpressionHandler<T> extends AopInfrastructureBean {
    /**
     * @return an expression parser for the expressions used by the implementation.
     */
    ExpressionParser getExpressionParser();

    /**
     * Provides an evaluation context in which to evaluate security expressions for the invocation type.
     */
    EvaluationContext createEvaluationContext(Authentication authentication, T invocation);
}
