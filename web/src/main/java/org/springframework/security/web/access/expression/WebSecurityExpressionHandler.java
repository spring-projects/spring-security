package org.springframework.security.web.access.expression;

import org.springframework.expression.EvaluationContext;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;

@Deprecated
public interface WebSecurityExpressionHandler extends SecurityExpressionHandler<FilterInvocation> {

    EvaluationContext createEvaluationContext(Authentication authentication, FilterInvocation invocation);
}
