package org.springframework.security.expression.support;

import org.springframework.expression.Expression;
import org.springframework.expression.ParseException;
import org.springframework.expression.spel.SpelExpressionParser;
import org.springframework.security.ConfigAttribute;

public class WebExpressionConfigAttribute implements ConfigAttribute {
    private final Expression authorizeExpression;

    public WebExpressionConfigAttribute(String authorizeExpression) throws ParseException {
        this.authorizeExpression = new SpelExpressionParser().parseExpression(authorizeExpression);
    }

    public WebExpressionConfigAttribute(Expression authorizeExpression) {
        this.authorizeExpression = authorizeExpression;
    }

    Expression getAuthorizeExpression() {
        return authorizeExpression;
    }

    public String getAttribute() {
        return null;
    }

}
