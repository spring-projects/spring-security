package org.springframework.security.expression.support;

import org.springframework.expression.Expression;
import org.springframework.expression.ParseException;
import org.springframework.expression.spel.SpelExpressionParser;
import org.springframework.security.ConfigAttribute;
import org.springframework.util.Assert;

/**
 * Contains both filtering and authorization expression meta-data for Spring-EL based access control.
 * <p>
 * Base class for pre or post-invocation phases of a method invocation.
 * <p>
 * Either filter or authorization expressions may be null, but not both.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
abstract class AbstractExpressionBasedMethodConfigAttribute implements ConfigAttribute {
    private final Expression filterExpression;
    private final Expression authorizeExpression;

    /**
     * Parses the supplied expressions as Spring-EL.
     */
    AbstractExpressionBasedMethodConfigAttribute(String filterExpression, String authorizeExpression) throws ParseException {
        Assert.isTrue(filterExpression != null || authorizeExpression != null, "Filter and authorization Expressions cannot both be null");
        SpelExpressionParser parser = new SpelExpressionParser();
        this.filterExpression = filterExpression == null ? null : parser.parseExpression(filterExpression);
        this.authorizeExpression = authorizeExpression == null ? null : parser.parseExpression(authorizeExpression);
    }

    AbstractExpressionBasedMethodConfigAttribute(Expression filterExpression, Expression authorizeExpression) throws ParseException {
        Assert.isTrue(filterExpression != null || authorizeExpression != null, "Filter and authorization Expressions cannot both be null");
        SpelExpressionParser parser = new SpelExpressionParser();
        this.filterExpression = filterExpression == null ? null : filterExpression;
        this.authorizeExpression = authorizeExpression == null ? null : authorizeExpression;
    }

    Expression getFilterExpression() {
        return filterExpression;
    }

    Expression getAuthorizeExpression() {
        return authorizeExpression;
    }

    public String getAttribute() {
        return null;
    }
}
