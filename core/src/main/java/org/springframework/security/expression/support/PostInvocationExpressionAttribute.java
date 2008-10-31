package org.springframework.security.expression.support;

import org.springframework.expression.ParseException;

class PostInvocationExpressionAttribute extends AbstractExpressionBasedMethodConfigAttribute {

    PostInvocationExpressionAttribute(String filterExpression, String authorizeExpression)
            throws ParseException {
        super(filterExpression, authorizeExpression);
    }

}
