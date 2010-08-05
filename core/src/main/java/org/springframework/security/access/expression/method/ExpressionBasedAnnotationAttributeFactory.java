/**
 *
 */
package org.springframework.security.access.expression.method;

import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.ParseException;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PostInvocationAttribute;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
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

    public PreInvocationAttribute createPreInvocationAttribute(PreFilter preFilter, PreAuthorize preAuthorize) {
        try {
         // TODO: Optimization of permitAll
            Expression preAuthorizeExpression = preAuthorize == null ? parser.parseExpression("permitAll") : parser.parseExpression(preAuthorize.value());
            Expression preFilterExpression = preFilter == null ? null : parser.parseExpression(preFilter.value());
            String filterObject = preFilter == null ? null : preFilter.filterTarget();
            return new PreInvocationExpressionAttribute(preFilterExpression, filterObject, preAuthorizeExpression);
        } catch (ParseException e) {
            throw new IllegalArgumentException("Failed to parse expression '" + e.getExpressionString() + "'", e);
        }
    }

    public PostInvocationAttribute createPostInvocationAttribute(PostFilter postFilter, PostAuthorize postAuthorize) {
        try {
            Expression postAuthorizeExpression = postAuthorize == null ? null : parser.parseExpression(postAuthorize.value());
            Expression postFilterExpression = postFilter == null ? null : parser.parseExpression(postFilter.value());

            if (postFilterExpression != null || postAuthorizeExpression != null) {
                return new PostInvocationExpressionAttribute(postFilterExpression, postAuthorizeExpression);
            }
        } catch (ParseException e) {
            throw new IllegalArgumentException("Failed to parse expression '" + e.getExpressionString() + "'", e);
        }

        return null;
    }
}
