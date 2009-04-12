package org.springframework.security.access.expression.method;

import org.springframework.expression.Expression;
import org.springframework.expression.ParseException;

class PostInvocationExpressionAttribute extends AbstractExpressionBasedMethodConfigAttribute {

    PostInvocationExpressionAttribute(String filterExpression, String authorizeExpression)
            throws ParseException {
        super(filterExpression, authorizeExpression);
    }

    PostInvocationExpressionAttribute(Expression filterExpression, Expression authorizeExpression)
                    throws ParseException {
        super(filterExpression, authorizeExpression);
    }
}
