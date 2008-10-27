package org.springframework.security.expression.support;

import org.springframework.expression.ParseException;

class PreInvocationExpressionConfigAttribute extends AbstractExpressionBasedMethodConfigAttribute {
    private final String filterTarget;

    PreInvocationExpressionConfigAttribute(String filterExpression, String filterTarget, String authorizeExpression)
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
