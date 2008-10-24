package org.springframework.security.expression.support;

import org.springframework.expression.ParseException;

class PostInvocationExpressionBasedMethodConfigAttribute extends AbstractExpressionBasedMethodConfigAttribute {

    PostInvocationExpressionBasedMethodConfigAttribute(String filterExpression, String authorizeExpression)
            throws ParseException {
        super(filterExpression, authorizeExpression);
    }

}
