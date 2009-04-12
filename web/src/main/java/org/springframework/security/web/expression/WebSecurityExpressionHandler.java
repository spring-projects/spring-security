package org.springframework.security.web.expression;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.security.Authentication;
import org.springframework.security.web.FilterInvocation;

public interface WebSecurityExpressionHandler {
    /**
     * @return an expression parser for the expressions used by the implementation.
     */
    ExpressionParser getExpressionParser();

    /**
     * Provides an evaluation context in which to evaluate security expressions for a web invocation.
     */
    EvaluationContext createEvaluationContext(Authentication authentication, FilterInvocation fi);

}
