/**
 *
 */
package org.springframework.security.access.expression.method;

import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.ParseException;
import org.springframework.security.access.prepost.PostInvocationAttribute;
import org.springframework.security.access.prepost.PreInvocationAttribute;
import org.springframework.security.access.prepost.PrePostInvocationAttributeFactory;

/**
 * {@link PrePostInvocationAttributeFactory} which interprets the annotation value as
 * an expression to be evaluated at runtime.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class ExpressionBasedAnnotationAttributeFactory implements PrePostInvocationAttributeFactory {
    private final ExpressionParser parser;

    public ExpressionBasedAnnotationAttributeFactory(MethodSecurityExpressionHandler handler) {
        parser = handler.getExpressionParser();
    }

    public PreInvocationAttribute createPreInvocationAttribute(String preFilterAttribute, String filterObject, String preAuthorizeAttribute) {
        try {
         // TODO: Optimization of permitAll
            Expression preAuthorizeExpression = preAuthorizeAttribute == null ? parser.parseExpression("permitAll") : parser.parseExpression(preAuthorizeAttribute);
            Expression preFilterExpression = preFilterAttribute == null ? null : parser.parseExpression(preFilterAttribute);
            return new PreInvocationExpressionAttribute(preFilterExpression, filterObject, preAuthorizeExpression);
        } catch (ParseException e) {
            throw new IllegalArgumentException("Failed to parse expression '" + e.getExpressionString() + "'", e);
        }
    }

    public PostInvocationAttribute createPostInvocationAttribute(String postFilterAttribute, String postAuthorizeAttribute) {
        try {
            Expression postAuthorizeExpression = postAuthorizeAttribute == null ? null : parser.parseExpression(postAuthorizeAttribute);
            Expression postFilterExpression = postFilterAttribute == null ? null : parser.parseExpression(postFilterAttribute);

            if (postFilterExpression != null || postAuthorizeExpression != null) {
                return new PostInvocationExpressionAttribute(postFilterExpression, postAuthorizeExpression);
            }
        } catch (ParseException e) {
            throw new IllegalArgumentException("Failed to parse expression '" + e.getExpressionString() + "'", e);
        }

        return null;
    }
}
