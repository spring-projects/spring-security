package org.springframework.security.access.expression;

import org.springframework.context.ApplicationContext;
import org.springframework.expression.AccessException;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.PropertyAccessor;
import org.springframework.expression.TypedValue;

/**
 * General property accessor which resolves properties as bean names within an {@code ApplicationContext}.
 */
final class ApplicationContextPropertyAccessor implements PropertyAccessor {
    private final ApplicationContext ctx;

    ApplicationContextPropertyAccessor(ApplicationContext ctx) {
        this.ctx = ctx;
    }

    public boolean canRead(EvaluationContext context, Object target, String name) throws AccessException {
        if (ctx == null) {
            return false;
        }

        return ctx.containsBean(name);
    }

    public TypedValue read(EvaluationContext context, Object target, String name) throws AccessException {
        return new TypedValue(ctx.getBean(name));
    }

    public boolean canWrite(EvaluationContext context, Object target, String name) throws AccessException {
        return false;
    }

    public void write(EvaluationContext context, Object target, String name, Object newValue) throws AccessException {
    }

    public Class[] getSpecificTargetClasses() {
        return null;
    }

}
