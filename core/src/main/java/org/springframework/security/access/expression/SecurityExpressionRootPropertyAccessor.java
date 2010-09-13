package org.springframework.security.access.expression;

import org.springframework.context.ApplicationContext;
import org.springframework.expression.AccessException;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.PropertyAccessor;
import org.springframework.expression.TypedValue;

@SuppressWarnings("unchecked")
final class SecurityExpressionRootPropertyAccessor implements PropertyAccessor {
    public final Class[] CLASSES = {SecurityExpressionRoot.class};

    public boolean canRead(EvaluationContext context, Object target, String name) throws AccessException {
        ApplicationContext ctx = ((SecurityExpressionRoot)target).getApplicationContext();

        if (ctx == null) {
            return false;
        }

        return ctx.containsBean(name);
    }

    public TypedValue read(EvaluationContext context, Object target, String name) throws AccessException {
        return new TypedValue(((SecurityExpressionRoot)target).getApplicationContext().getBean(name));
    }

    public boolean canWrite(EvaluationContext context, Object target, String name) throws AccessException {
        return false;
    }

    public void write(EvaluationContext context, Object target, String name, Object newValue) throws AccessException {
    }

    public Class[] getSpecificTargetClasses() {
        return CLASSES;
    }

}
