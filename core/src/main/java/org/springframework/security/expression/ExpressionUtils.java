package org.springframework.security.expression;

import java.lang.reflect.Array;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.springframework.expression.EvaluationException;
import org.springframework.expression.Expression;
import org.springframework.expression.spel.standard.StandardEvaluationContext;

public class ExpressionUtils {
    public static Object doFilter(Object filterTarget, Expression filterExpression, StandardEvaluationContext ctx) {
        SecurityExpressionRoot rootObject = (SecurityExpressionRoot) ctx.getRootContextObject();
        Set removeList = new HashSet();

        if (filterTarget instanceof Collection) {
            for (Object filterObject : (Collection)filterTarget) {
                rootObject.setFilterObject(filterObject);

                if (!evaluateAsBoolean(filterExpression, ctx)) {
                    removeList.add(filterObject);
                }
            }

            for(Object toRemove : removeList) {
                ((Collection)filterTarget).remove(toRemove);
            }

            return filterTarget;
        }

        if (filterTarget.getClass().isArray()) {
            Object[] array = (Object[])filterTarget;

            for (int i = 0; i < array.length; i++) {
                rootObject.setFilterObject(array[i]);

                if (!evaluateAsBoolean(filterExpression, ctx)) {
                    removeList.add(array[i]);
                }
            }

            Object[] filtered = (Object[]) Array.newInstance(filterTarget.getClass().getComponentType(),
                    array.length - removeList.size());
            for (int i = 0, j = 0; i < array.length; i++) {
                if (!removeList.contains(array[i])) {
                    filtered[j++] = array[i];
                }
            }

            return filtered;
        }

        throw new IllegalArgumentException("Filter target must be a collection or array type, but was " + filterTarget);
    }

    public static boolean evaluateAsBoolean(Expression expr, StandardEvaluationContext ctx) {
        try {
            return ((Boolean) expr.getValue(ctx, Boolean.class)).booleanValue();
        } catch (EvaluationException e) {
            throw new IllegalArgumentException("Failed to evaluate expression", e);
        }
    }


}
