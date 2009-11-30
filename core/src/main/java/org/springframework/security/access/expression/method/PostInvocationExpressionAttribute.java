package org.springframework.security.access.expression.method;

import org.springframework.expression.Expression;
import org.springframework.expression.ParseException;
import org.springframework.security.access.prepost.PostInvocationAttribute;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
class PostInvocationExpressionAttribute extends AbstractExpressionBasedMethodConfigAttribute
        implements PostInvocationAttribute {

    PostInvocationExpressionAttribute(String filterExpression, String authorizeExpression)
            throws ParseException {
        super(filterExpression, authorizeExpression);
    }

    PostInvocationExpressionAttribute(Expression filterExpression, Expression authorizeExpression)
                    throws ParseException {
        super(filterExpression, authorizeExpression);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        Expression authorize = getAuthorizeExpression();
        Expression filter = getFilterExpression();
        sb.append("[authorize: '").append(authorize == null ? "null" : authorize.getExpressionString());
        sb.append("', filter: '").append(filter == null ? "null" : filter.getExpressionString()).append("']");
        return sb.toString();
    }
}
