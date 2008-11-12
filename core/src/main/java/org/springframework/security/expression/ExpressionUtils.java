package org.springframework.security.expression;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.EvaluationException;
import org.springframework.expression.Expression;

public class ExpressionUtils {

    public static boolean evaluateAsBoolean(Expression expr, EvaluationContext ctx) {
        try {
            return ((Boolean) expr.getValue(ctx, Boolean.class)).booleanValue();
        } catch (EvaluationException e) {
            throw new IllegalArgumentException("Failed to evaluate expression", e);
        }
    }
}
