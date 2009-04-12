package org.springframework.security.access.expression.method;

import org.springframework.expression.Expression;
import org.springframework.expression.ParseException;

class PreInvocationExpressionAttribute extends AbstractExpressionBasedMethodConfigAttribute {
    private final String filterTarget;

    PreInvocationExpressionAttribute(String filterExpression, String filterTarget, String authorizeExpression)
            throws ParseException {
        super(filterExpression, authorizeExpression);

        this.filterTarget = filterTarget;
    }

    PreInvocationExpressionAttribute(Expression filterExpression, String filterTarget, Expression authorizeExpression)
            throws ParseException {
        super(filterExpression, authorizeExpression);

        this.filterTarget = filterTarget;
    }

    /**
     * The parameter name of the target argument (must be a Collection) to which filtering will be applied.
     *
     * @return the method parameter name
     */
    String getFilterTarget() {
        return filterTarget;
    }
}
