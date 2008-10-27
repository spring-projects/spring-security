package org.springframework.security.expression.support;

import org.springframework.expression.ParseException;

class PostInvocationExpressionConfigAttribute extends AbstractExpressionBasedMethodConfigAttribute {

    PostInvocationExpressionConfigAttribute(String filterExpression, String authorizeExpression)
            throws ParseException {
        super(filterExpression, authorizeExpression);
    }

}
