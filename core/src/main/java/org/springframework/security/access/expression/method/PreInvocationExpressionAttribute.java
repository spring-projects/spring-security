package org.springframework.security.access.expression.method;

import org.springframework.expression.Expression;
import org.springframework.expression.ParseException;
import org.springframework.security.access.prepost.PreInvocationAttribute;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
class PreInvocationExpressionAttribute extends AbstractExpressionBasedMethodConfigAttribute
        implements PreInvocationAttribute {

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
