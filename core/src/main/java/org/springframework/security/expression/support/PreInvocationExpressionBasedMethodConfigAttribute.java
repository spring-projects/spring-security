package org.springframework.security.expression.support;

import org.springframework.expression.ParseException;

class PreInvocationExpressionBasedMethodConfigAttribute extends AbstractExpressionBasedMethodConfigAttribute {
    private final String filterTarget;

    PreInvocationExpressionBasedMethodConfigAttribute(String filterExpression, String filterTarget,
            String authorizeExpression) throws ParseException {
        super(filterExpression, authorizeExpression);

        this.filterTarget = filterTarget;
    }

    String getFilterTarget() {
        return filterTarget;
    }
}
