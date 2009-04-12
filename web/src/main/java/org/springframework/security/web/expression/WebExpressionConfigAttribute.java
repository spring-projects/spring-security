package org.springframework.security.web.expression;

import org.springframework.expression.Expression;
import org.springframework.security.access.ConfigAttribute;

/**
 * Simple expression configuration attribute for use in web request authorizations.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
class WebExpressionConfigAttribute implements ConfigAttribute {
    private final Expression authorizeExpression;

    public WebExpressionConfigAttribute(Expression authorizeExpression) {
        this.authorizeExpression = authorizeExpression;
    }

    Expression getAuthorizeExpression() {
        return authorizeExpression;
    }

    public String getAttribute() {
        return null;
    }

    @Override
    public String toString() {
        return authorizeExpression.getExpressionString();
    }
}
